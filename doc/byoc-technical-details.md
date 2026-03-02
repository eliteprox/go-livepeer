# BYOC Technical Details

This document is an implementation-level reference for **Bring Your Own Container (BYOC)** in
go-livepeer. For a quick-start tutorial see [`doc/byoc.md`](byoc.md), and for the Gateway
stream API reference see [`doc/byoc-streaming.md`](byoc-streaming.md).

---

## 1. Overview

BYOC lets an external worker process register itself with a Livepeer Orchestrator at runtime.
The Orchestrator then advertises that capability to Gateways, which can route paid jobs to it
through the standard Livepeer payment pipeline.

`Capability_BYOC = 37` (`core/capabilities.go:91`) is a sentinel value used to tag BYOC price
entries in the capability price list. It is **not** a real pipeline — no built-in code handles
it as a workload. Its sole job is to distinguish externally-registered capability prices from
built-in AI capability prices when serialised over the network.

---

## 2. Architecture: Two Models

BYOC supports two interaction patterns. Choose the one that fits your workload.

### Job Model (Batch / Request–Response)

- **When to use**: stateless, discrete tasks — LLM inference, text processing, image analysis,
  audio transcription, etc.
- The Gateway receives a `POST /process/request/<sub-path>` and proxies it through an
  Orchestrator to the worker's base URL.
- The whole round-trip lives inside a single HTTP request (or an SSE stream for long-running
  jobs).
- Payment is charged once at the end based on wall-clock seconds elapsed.

### Stream Model (Long-Running / Stateful)

- **When to use**: continuous data feeds — live video processing, real-time inference loops,
  persistent pipelines.
- A `POST /process/stream/start` on the Gateway opens a persistent session identified by a
  `streamId`.
- Media is exchanged over **Trickle** pub/sub channels that live on the Orchestrator.
- Payment is debited on a running clock: the Orchestrator debits every 23 s, the Gateway tops
  up every 50 s.

---

## 3. Registration

### `POST /capability/register`

Served by the **Orchestrator** at `BYOCOrchestratorServer.RegisterCapability()`
(`byoc/job_orchestrator.go:32`).

**Authentication**: `Authorization: <orchSecret>` header — the same secret used for transcoder
attachment.

**Request body** (JSON): maps directly to `ExternalCapability` (`core/external_capabilities.go:17`):

```json
{
  "name":           "my-pipeline",
  "description":    "human-readable description",
  "url":            "http://worker-host:5000",
  "capacity":       4,
  "price_per_unit": 1,
  "price_scaling":  600,
  "currency":       "USD"
}
```

| Field           | Type   | Description |
|-----------------|--------|-------------|
| `name`          | string | Unique capability identifier; used as routing key. |
| `description`   | string | Free-form, not used by routing logic. |
| `url`           | string | Base URL of the worker. Sub-paths are appended by the Orchestrator. |
| `capacity`      | int    | Maximum concurrent jobs. Managed via `Load` counter. |
| `price_per_unit`| int64  | Numerator of price fraction. |
| `price_scaling` | int64  | Denominator of price fraction (defaults to 1 if 0). |
| `currency`      | string | Currency code for auto-conversion (e.g. `"USD"`, `"ETH"`, `"wei"`). |

### Storage

Registrations are stored in two places on the Orchestrator node:

1. **`ExternalCapabilities.Capabilities`** (`core/external_capabilities.go:106`) — a
   `map[string]*ExternalCapability` keyed by capability name. Holds the URL, capacity, and
   computed price.
2. **`jobPriceInfo`** (`core/livepeernode.go:366`) — a `map[senderEthAddr]map[capName]*big.Rat`
   used to look up the price when building payment responses. Populated via
   `SetPriceForExternalCapability`.

### Re-registration Behaviour

`RegisterCapability` (`core/external_capabilities.go:198`) uses **last-writer-wins** semantics:
the incoming registration always overwrites the stored entry. Notably, the replacement struct
starts with `Load = 0`, so any active-job tracking is silently lost. Workers should not
re-register while jobs are in flight.

### `POST /capability/unregister`

Request body: plain-text capability name. Removes the entry from `ExternalCapabilities.Capabilities`.

---

## 4. BYOC vs Built-in AI Capabilities

The table below compares BYOC against representative built-in AI capabilities to show where
the implementation differs.

| Property | LLM (33) | TextToImage (27) | AudioToText (31) | LiveVideoToVideo (35) | **BYOC (37)** |
|---|---|---|---|---|---|
| Registration time | Node startup (config file) | Node startup | Node startup | Node startup | **Runtime (`POST /capability/register`)** |
| In capability bitstring | Yes | Yes | Yes | Yes | **No** |
| `PerCapability` constraints (model IDs) | Yes | Yes | Yes | Yes | **No** |
| Warm/cold session routing | Yes | Yes | Yes | Yes (warm only) | **No** |
| Price store | `priceInfoForCaps` | `priceInfoForCaps` | `priceInfoForCaps` | `priceInfoForCaps` | **`jobPriceInfo`** |
| Capacity tracking | `Capacities` map in `Capabilities` | same | same | `Capacities` map | **`ExternalCapability.Load`** |
| Per-gateway price override | Yes (`priceInfoForCaps[ethAddr]`) | Yes | Yes | Yes | **No** |

Key implications:

- **Bitstring absence**: `Capability_BYOC` is never set in a node's capability bitstring, so
  BYOC capabilities never appear in `CompatibleWith` filtering. Gateways discover BYOC
  capabilities through the price list alone (`Capability_BYOC` + capability name as
  `Constraint`).
- **No per-gateway price override**: built-in capabilities allow different prices per
  Gateway ETH address via `priceInfoForCaps`. BYOC uses `jobPriceInfo` which is populated
  from the registration payload and has no per-gateway variant.

---

## 5. Job Model (Batch / Request–Response)

### Gateway Route

```
/process/request/          →  SubmitJob()   (byoc/job_gateway.go)
/process/request/<sub-path>
```

The Gateway:
1. Looks up available Orchestrators that advertise the requested BYOC capability.
2. Signs the job request and forwards it to the Orchestrator's `/process/request/<sub-path>`.

### Orchestrator Processing (`byoc/job_orchestrator.go`)

Per-call steps in `processJob`:

1. **Signature verification** (`verifyJobCreds`): decodes the `Livepeer` header, checks the
   sender's Ethereum signature over `request + parameters`.
2. **Capacity reservation** (`ReserveExternalCapabilityCapacity`): atomically increments
   `ExternalCapability.Load`; returns `503` if `Load >= Capacity`.
3. **Payment verification** (`confirmPayment`): processes any ticket in the
   `Livepeer-Payment` header and checks that the resulting balance covers at least 60 seconds
   of compute at the registered rate.
4. **Sub-path forwarding**: strips the `/process/request/` prefix and appends the remainder
   to the worker base URL:
   ```go
   // byoc/job_orchestrator.go:261
   workerRoute = workerRoute + "/" + workerResourceRoute
   ```
5. **Response proxy**: for non-SSE responses, reads the full body, charges for compute, and
   returns. For SSE responses, streams lines to the client.

### SSE Streaming

When the worker response is `Content-Type: text/event-stream`, the Orchestrator:

- Forwards lines from the worker to the client in real time.
- Runs a **balance ticker every 5 seconds** that debits `rate × 5` from the sender's balance.
  If balance goes negative the stream is terminated with an `insufficient balance` event.
- Injects a final `data: {"balance": <n>}` line just before `[DONE]`.

### Job Charge

`chargeForCompute` (`byoc/job_orchestrator.go:507`):

```go
took := time.Since(start)
orch.DebitFees(sender, manifestID, price, int64(math.Ceil(took.Seconds())))
```

Charge = `rate × ⌈seconds⌉`. Applied on every exit path (success, worker error, connection
error).

---

## 6. Stream Model (Long-Running)

### Gateway Routes (`byoc/byoc.go:164`)

```
POST /process/stream/start
POST /process/stream/{streamId}/update
POST /process/stream/{streamId}/stop
POST /process/stream/{streamId}/status    (GET)
POST /process/stream/{streamId}/data      (GET, SSE)
POST /process/stream/{streamId}/rtmp
POST /process/stream/{streamId}/whip
```

### Orchestrator Routes (`byoc/byoc.go:225`)

```
POST /ai/stream/start
POST /ai/stream/stop
POST /ai/stream/update
POST /ai/stream/payment
```

### Trickle Channel Setup

On `/ai/stream/start` the Orchestrator creates Trickle channels on its local trickle server
and passes the URLs back to the Gateway in response headers. Channels are created
conditionally based on `JobParameters` flags:

| Channel | Flag | Direction | MIME type | Response header |
|---------|------|-----------|-----------|-----------------|
| **pub** (video ingress) | `enable_video_ingress` | Gateway → Worker | `video/MP2T` | `X-Publish-Url` |
| **sub** (video egress) | `enable_video_egress` | Worker → Gateway | `video/MP2T` | `X-Subscribe-Url` |
| **control** | always | Gateway → Worker | `application/json` | `X-Control-Url` |
| **events** | always | Worker → Gateway | `application/json` | `X-Events-Url` |
| **data** | `enable_data_output` | Worker → Gateway | `application/jsonl` | `X-Data-Url` |

The worker receives all enabled channel URLs in the body of `POST {url}/stream/start` as JSON
fields (`subscribe_url`, `publish_url`, `control_url`, `events_url`, `data_url`).

### State Lifecycle

```
Gateway                              Orchestrator
─────────────────────────────────── ─────────────────────────────────────
BYOCStreamPipelines[streamId]       ExternalCapabilities.Streams[streamId]
  (created on POST /process/stream/start)   (created on POST /ai/stream/start)
  cancelled on stop/error              cancelled on stop/balance-zero
```

The Gateway's `monitorStream` goroutine owns the pipeline lifecycle and calls
`removeStreamPipeline` on teardown. The Orchestrator's `monitorOrchStream` goroutine owns
the `Streams` entry and calls `RemoveStream` on teardown.

---

## 7. Worker API Contract

The external worker must expose an HTTP server at the URL registered in
`POST /capability/register`.

### Job Model

No specific path contract — the worker may expose any paths. The Orchestrator appends whatever
sub-path the client used after `/process/request/` and forwards the full request body and
`Content-Type` header unchanged.

### Stream Model

The Orchestrator calls the following fixed paths relative to the registered worker URL:

| Method | Path | When called | Body |
|--------|------|-------------|------|
| `POST` | `{url}/stream/start` | Stream start | JSON with trickle URLs + original client body merged |
| `POST` | `{url}/stream/stop` | Stream stop | Original client stop body |
| `POST` | `{url}/stream/params` | Stream update | Original client update body |

**Headers passed through on all stream calls:**

- `X-Stream-Id` — the stream identifier, useful when a reverse proxy sits in front of multiple
  worker instances.
- `Content-Type` — forwarded from the Gateway client request.

The `stream/start` body includes:

```json
{
  "gateway_request_id": "<id>",
  "control_url":   "<trickle-url>",
  "events_url":    "<trickle-url>",
  "subscribe_url": "<trickle-url>",  // only if enable_video_ingress
  "publish_url":   "<trickle-url>",  // only if enable_video_egress
  "data_url":      "<trickle-url>",  // only if enable_data_output
  // ... original client body fields merged in
}
```

---

## 8. Payment System

### Registration Fields

```json
{
  "price_per_unit": 1,
  "price_scaling":  600,
  "currency":       "USD"
}
```

These form a rational number `PricePerUnit / PriceScaling`. The `currency` field drives
automatic fiat-to-wei conversion via `AutoConvertedPrice`.

### Core Formula

```
cost = (PricePerUnit / PriceScaling) × seconds
```

For example, `price_per_unit=1, price_scaling=600, currency="USD"` means
`1/600 USD per second = $0.10/minute = $6.00/hour`.

### `DebitFees` Implementation (`core/orchestrator.go:475`)

```go
priceRat := big.NewRat(price.GetPricePerUnit(), price.GetPixelsPerUnit())
node.Balances.Debit(addr, manifestID, priceRat.Mul(priceRat, big.NewRat(pixels, 1)))
```

`PixelsPerUnit` is the field name inherited from the video transcoding world; in BYOC it acts
as the price scaling denominator (seconds-based), not a pixel count. The `units` argument
passed to `DebitFees` is always a number of seconds.

### Stream Payment Lifecycle

```
t=0        Stream start request arrives
           └─ confirmPayment checks balance ≥ rate × 60  (1 min pre-fund gate)
           └─ chargeForCompute debits rate × ⌈start_latency_secs⌉

t+23s      Orchestrator monitorOrchStream ticker fires
           └─ DebitFees(sender, capability, price, 23)
           └─ if balance < 0: warn, set shouldStopNextRound=true

t+46s      Orchestrator ticker fires again
           └─ DebitFees again
           └─ if balance still < 0 AND shouldStopNextRound: RemoveStream → stop

t+50s      Gateway monitorStream ticker fires
           └─ getToken → fetch fresh ticket params + orchestrator balance
           └─ createPayment → ticket batch covering next interval
           └─ POST /ai/stream/payment with payment header

           /ai/stream/payment handler:
           └─ validates request, then ONLY returns current balance in header
           └─ does NOT debit — debit is the Orchestrator's responsibility
```

**Balance gate**: `minBal = rate × 60` (`byoc/job_orchestrator.go:470`). A stream is
rejected with `402 Payment Required` if the sender's balance is below this threshold at
stream start.

**Cutoff**: two consecutive negative-balance rounds on the Orchestrator (~46 s of grace after
the balance goes negative).

**Gateway payment interval**: 50 s (`stream_gateway.go:321`).

**Orchestrator debit interval**: 23 s (`stream_orchestrator.go:233`).

### Job Payment

```
chargeForCompute(start, price, sender, capability)
  ← rate × ⌈time.Since(start).Seconds()⌉
```

Applied once at the end of the request on all exit paths (success, error, timeout).

### Worked Example

Rate: **$0.10 per minute**

```json
{
  "price_per_unit": 1,
  "price_scaling":  600,
  "currency":       "USD"
}
```

| Metric | Value |
|--------|-------|
| Rate (wei/s) | `AutoConvert(1/600 USD)` |
| Minimum deposit (1 min pre-fund) | $0.10 |
| Hourly cost | $6.00 |
| Cost of a 7 s job | `rate × ⌈7⌉ = rate × 7` ≈ $0.012 |

For a free tier (no payment required), set `price_per_unit=0`.

---

## 9. Limitations and Gotchas

### Single URL per Capability Name

`ExternalCapabilities.Capabilities` is keyed by `name`. There is no built-in load balancing
across multiple worker URLs for the same capability. If you need horizontal scaling, put a
reverse proxy behind a single registered URL or register each worker under a distinct name.

### Re-registration Resets the Load Counter

`RegisterCapability` replaces the stored `*ExternalCapability` with a fresh struct whose
`Load` field is 0. Any jobs currently counted against the old struct lose their tracking.
Re-registering while jobs are in flight can cause `Load` to go negative (via `FreeExternalCapabilityCapacity`), permitting more concurrent jobs than `capacity` allows.

### No Per-Gateway Price Override

Built-in AI capabilities support different prices per Gateway ETH address via
`priceInfoForCaps[ethAddr]`. BYOC uses `jobPriceInfo` populated from the registration payload;
there is no mechanism to charge different Gateways different rates for the same BYOC
capability.

### `Capability_BYOC` Never Appears in the Capability Bitstring

Because `Capability_BYOC` is never set in the node's `CapabilityString`, Orchestrators that
support BYOC capabilities will not match on `CompatibleWith` bitstring checks. Gateways
discover BYOC availability through the `CapabilitiesPrices` list (where BYOC entries use
`Capability=37` and the capability name as `Constraint`), not through bitstring filtering.

---

## Key Files Reference

| File | What it contains |
|------|-----------------|
| `core/external_capabilities.go` | `ExternalCapability`, `ExternalCapabilities`, `StreamInfo`, `RegisterCapability` |
| `core/orchestrator.go:258` | `GetCapabilitiesPrices` — injects BYOC prices into the network advertisement |
| `core/orchestrator.go:475` | `DebitFees` implementation |
| `core/livepeernode.go:366` | `SetPriceForExternalCapability`, `GetPriceForJob`, `jobPriceInfo` map |
| `core/capabilities.go:87–133` | Capability enum and `CapabilityNameLookup` |
| `common/types.go:172` | `OrchNetworkCapabilities` — the wire format for capability discovery |
| `byoc/byoc.go` | Route registration for Gateway (`BYOCGatewayServer`) and Orchestrator (`BYOCOrchestratorServer`) |
| `byoc/types.go` | `JobRequest`, `JobParameters`, `BYOCStreamPipeline`, header constants |
| `byoc/job_orchestrator.go` | `ProcessJob`, `processJob`, `setupOrchJob`, `confirmPayment`, `chargeForCompute` |
| `byoc/stream_orchestrator.go` | `StartStream`, `monitorOrchStream`, `ProcessStreamPayment` |
| `byoc/stream_gateway.go` | `monitorStream`, `sendPaymentForStream`, `setupStream` |
| `byoc/payment.go` | `createPayment`, `updateGatewayBalance`, `ticketCountForCost` |
| `core/ai_orchestrator.go:1151` | `CheckExternalCapabilityCapacity`, `ReserveExternalCapabilityCapacity`, `FreeExternalCapabilityCapacity` |
