# Simple BYOC Worker Example

A minimal BYOC (Bring Your Own Container) worker and registration flow. See [doc/byoc.md](../../doc/byoc.md) for full documentation.

## Quick Start (orchestrator and gateway on host for debugging)

The stack assumes your orchestrator and gateway run on the host. Worker and register use `network_mode: host` so they reach them at localhost.

1. Start your orchestrator on the host (e.g. port 8935, `-orchSecret=orch-secret`).
2. Start your gateway on the host (e.g. port 9935).

3. From this directory:

```bash
docker compose up
```

This starts:

- **worker** – Text-reversal Flask service on `localhost:5000`
- **register** – Registers the `text-reversal` capability with your host orchestrator

Set `ORCHESTRATOR_PORT` if your orchestrator uses a different port than 8935.

## Test

After all services are up:

```bash
curl -X POST http://localhost:9935/process/request/reverse-text \
  -H "Content-Type: application/json" \
  -H "Livepeer: eyJyZXF1ZXN0IjogIntcInJ1blwiOiBcImVjaG9cIn0iLCAiY2FwYWJpbGl0eSI6ICJ0ZXh0LXJldmVyc2FsIiwgInRpbWVvdXRfc2Vjb25kcyI6IDMwfQ==" \
  -d '{"text":"Hello, Livepeer BYOC!"}'
```

Expected response:

```json
{
  "original": "Hello, Livepeer BYOC!",
  "reversed": "!COYB reepevil ,olleH"
}
```

## Run Worker Only (for your own orchestrator)

Build and run the worker container:

```bash
docker build -f Dockerfile.worker -t byoc_reverse_text .
docker run -p 5000:5000 byoc_reverse_text
```

Register it manually (adjust `ORCHESTRATOR_URL` and `WORKER_URL` to your setup):

```bash
# With orchestrator at host:8935 and worker at host:5000
ORCHESTRATOR_URL="https://your-orch:8935"
WORKER_URL="http://your-worker:5000"

curl -X POST "$ORCHESTRATOR_URL/capability/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: orch-secret" \
  -d "{\"name\":\"text-reversal\",\"url\":\"$WORKER_URL\",\"capacity\":1,\"price_per_unit\":0,\"price_scaling\":1,\"currency\":\"wei\"}"
```
