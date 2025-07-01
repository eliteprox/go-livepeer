<!-- show-on-docup
<br />
-->

[![go-livepeer](https://user-images.githubusercontent.com/555740/117340053-78210e80-ae6e-11eb-892c-d98085fe6824.png)](https://github.com/livepeer/go-livepeer)

---
[![Go Report Card](https://goreportcard.com/badge/github.com/livepeer/go-livepeer)](https://goreportcard.com/report/github.com/livepeer/go-livepeer)
[![Discord](https://img.shields.io/discord/423160867534929930.svg?style=flat-square)](https://discord.gg/livepeer)
[![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg?style=flat-square)](CONTRIBUTING.md)

The Livepeer project aims to deliver a live video-streaming network protocol
that is fully decentralized, highly scalable and crypto-token incentivized to
serve as the live media layer in the decentralized development (Web3) stack.
[Read our documentation](https://docs.livepeer.org/protocol/) to learn more about the protocol and its economic incentives.

`go-livepeer` is a Go implementation of the [Livepeer](https://livepeer.org) protocol which powers the Livepeer Network. Specifically, `go-livepeer` contains implementations of Broadcaster, Orchestrator, and Transcoder nodes (roles) in the Livepeer Network ecosystem.

<!-- hide-on-docup-start -->

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [Resources](#resources)

<!-- hide-on-docup-stop -->

## Requirements

This project requires `go` and a unix shell.

- [Installing and Managing Go](doc/go.md)


## Getting Started

To get started, clone the repo and follow the [installation guide](https://docs.livepeer.org/guides/orchestrating/install-go-livepeer).

Next, follow [the guide to set up a private ETH network with the Livepeer protocol deployed](cmd/devtool/README.md).

## Contributing

Thanks for your interest in contributing to go-livepeer. There are many ways you can contribute to the project, even for non-developers.

To start, take a few minutes to **[read the "Contributing to go-livepeer" guide](CONTRIBUTING.md)**.

We look forward to your pull requests and / or involvement in our
[issues page](https://github.com/livepeer/go-livepeer/issues) and hope to see
your username on our
[list of contributors](https://github.com/livepeer/go-livepeer/graphs/contributors)
🎉🎉🎉

## Resources

To get a full idea of what Livepeer is about, be sure to take a look at these
other resources:

- 🌐 [The Livepeer Website](https://livepeer.org)
- 📖 [The Livepeer Docs](https://livepeer.org/docs)
- 🔭 [The 10-Minute Primer](https://livepeer.org/primer/)
- ✍ [The Livepeer Blog](https://medium.com/livepeer-blog)
- 💬 [The Livepeer Chat](https://discord.gg/livepeer)
- ❓ [The Livepeer Forum](https://forum.livepeer.org/)

# Livepeer WHIP-ingest Job Test Scripts

This repository contains test scripts for sending WHIP-ingest job requests to a Livepeer Gateway.

## Overview

These scripts demonstrate how to:
1. Generate a mock SDP offer for WHIP (WebRTC-HTTP Ingestion Protocol)
2. Create the proper JobRequest structure required by Livepeer
3. Send HTTP POST requests to the gateway endpoint
4. Handle different request body formats (raw SDP vs JSON)

## Files

- `test_whip_job.py` - Full implementation with proper cryptographic signing
- `simple_whip_test.py` - Simplified version for testing without crypto dependencies
- `requirements.txt` - Python package dependencies

## Prerequisites

### For Livepeer Gateway

1. **Running Livepeer Gateway**: You need a Livepeer Gateway running and accessible
2. **Orchestrators with WHIP capability**: At least one orchestrator must support the "whip-ingest" capability
3. **Network connectivity**: Gateway should be reachable on the configured port (default: 8935)

### For Test Scripts

**Simple Version** (`simple_whip_test.py`):
```bash
pip install requests
```

**Full Version** (`test_whip_job.py`):
```bash
pip install -r requirements.txt
```

## Usage

### Quick Test (Simple Version)

Use this for basic testing without cryptographic signing:

```bash
python simple_whip_test.py
```

This script:
- Uses mock signatures (will likely be rejected by real gateways)
- Tests basic connectivity and request format
- Useful for debugging gateway connectivity and request structure

### Full Test (With Signing)

Use this for testing with proper cryptographic signatures:

```bash
python test_whip_job.py
```

This script:
- Uses real Ethereum cryptographic signing
- Creates valid signatures for job requests
- More likely to work with production gateways

**Note**: The script uses a test private key. For production use, replace with your actual private key.

## Configuration

Both scripts can be configured by modifying the constants at the top:

```python
GATEWAY_URL = "http://localhost:8935"  # Change to your gateway URL
ENDPOINT = "/process/request/whip-ingest"  # WHIP endpoint path
```

## Request Format

The scripts demonstrate the required format for WHIP-ingest job requests:

### Job Request Structure
```json
{
  "id": "unique-job-id",
  "request": "{\"start_stream\":true,\"stream_id\":\"stream-123\"}",
  "parameters": "",
  "capability": "whip-ingest",
  "sender": "0x...",
  "sig": "0x...",
  "timeout_seconds": 120
}
```

### HTTP Headers
- `Livepeer`: Base64-encoded JobRequest JSON
- `Content-Type`: `application/sdp` (for raw SDP) or `application/json`
- `Livepeer-Orch-Search-Timeout`: Optional timeout for finding orchestrators
- `Livepeer-Orch-Search-Resp-Timeout`: Optional timeout for orchestrator responses

### Request Body Formats

**Format 1: Raw SDP**
```
Content-Type: application/sdp

v=0
o=- 123456789 2 IN IP4 127.0.0.1
s=-
...
```

**Format 2: JSON**
```json
{
  "sdp_offer": "v=0\r\no=- 123456789 2 IN IP4 127.0.0.1\r\n..."
}
```

## Expected Responses

### Success (201 Created)
```
Content-Type: application/sdp
Location: /whip/stream-id

v=0
o=- 987654321 2 IN IP4 127.0.0.1
s=-
... (SDP Answer)
```

### Common Error Responses

- **400 Bad Request**: Invalid job request format or missing required fields
- **403 Forbidden**: Invalid signature or unauthorized sender
- **503 Service Unavailable**: No orchestrators available for whip-ingest capability

## Troubleshooting

### Gateway Not Reachable
- Verify the gateway is running
- Check the `GATEWAY_URL` configuration
- Ensure the port is correct (default: 8935)

### Invalid Signature Errors
- Make sure you're using the full version with proper signing
- Verify the private key is valid
- Check that the message signing format matches the Go implementation

### No Orchestrators Available
- Ensure at least one orchestrator supports "whip-ingest" capability
- Check orchestrator registration and connectivity
- Verify orchestrator capacity is available

### SDP Format Issues
- The generated SDP is a mock for testing
- For real use, you'd need a proper WebRTC SDP offer
- Ensure SDP format matches WebRTC standards

## Development Notes

### Signing Implementation

The signing process follows the Go implementation:
1. Concatenate `request` + `parameters` fields
2. Hash with Keccak256: `crypto.Keccak256(message)`
3. Sign the hash with Ethereum private key
4. Encode signature as hex with "0x" prefix

### Mock SDP Generation

The scripts generate a basic VP8/VP9/H264 SDP offer suitable for testing. For production use, you'd typically:
- Use a WebRTC library to generate proper SDP
- Include real ICE candidates
- Set appropriate codec parameters

## License

This code is provided as-is for testing and educational purposes.
