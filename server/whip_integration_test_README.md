# WHIP/WHEP Integration Tests

This document describes the WHIP (WebRTC-HTTP Ingestion Protocol) and WHEP (WebRTC-HTTP Egress Protocol) integration tests for go-livepeer.

## Overview

The `whip_integration_test.go` file contains comprehensive tests for both the direct WHIP endpoints and the job-based WHIP/WHEP capabilities. These tests validate the WebRTC stream ingestion and egress functionality that works with the ComfyStream processing pipeline.

## Test Structure

### 1. Direct WHIP Endpoint Tests (`TestDirectWHIPEndpoint`)

Tests the direct WHIP endpoint: `/live/video-to-video/{stream}/whip`

**Test Cases:**
- **SuccessfulWHIPRequest**: Tests successful WHIP session creation with valid SDP offer
- **InvalidContentType**: Tests rejection of non-SDP content types
- **MissingStreamName**: Tests error handling for missing stream names
- **CORSHeaders**: Tests CORS header configuration

**Usage:**
```bash
go test ./server -run TestDirectWHIPEndpoint -v
```

### 2. Job-Based WHIP/WHEP Tests (`TestJobBasedWHIPEndpoint`)

Tests the job-based endpoints: `/process/request/whip-ingest` and `/process/request/whep-subscribe`

**Test Cases:**
- **WHIPIngestCapability**: Tests WHIP ingestion through the job system
- **WHEPSubscribeCapability**: Tests WHEP subscription through the job system
- **InvalidJobRequest**: Tests error handling for malformed job requests
- **MissingJobRequest**: Tests error handling for missing job headers

**Usage:**
```bash
go test ./server -run TestJobBasedWHIPEndpoint -v
```

### 3. Integration Tests (`TestWHIPWHEPIntegration`)

Tests the complete WHIP-to-WHEP flow for end-to-end validation.

**Usage:**
```bash
go test ./server -run TestWHIPWHEPIntegration -v
```

### 4. Routing Tests (`TestWHIPEndpointRouting`)

Tests that WHIP endpoints are properly routed and accessible.

**Usage:**
```bash
go test ./server -run TestWHIPEndpointRouting -v
```

### 5. Client Example (`TestWHIPClientExample`)

Demonstrates how to create WHIP requests programmatically, similar to the Python `whip_client_example.py`.

## How to Run Tests

### Prerequisites

1. **Go Environment**: Ensure Go 1.19+ is installed
2. **Dependencies**: Run `go mod download` to install dependencies
3. **Environment Variables**: 
   - Set `LIVE_AI_WHIP_ADDR=:8889` to enable WHIP endpoints
   - Set `LIVE_AI_ALLOW_CORS=true` for CORS testing (optional)

### Running Individual Test Suites

```bash
# Run all WHIP tests
go test ./server -run TestDirect -v
go test ./server -run TestJobBased -v
go test ./server -run TestWHIPWHEP -v

# Run specific test cases
go test ./server -run TestDirectWHIPEndpoint/SuccessfulWHIPRequest -v
go test ./server -run TestJobBasedWHIPEndpoint/WHIPIngestCapability -v
```

### Running Integration Tests

```bash
# Skip integration tests in short mode
go test ./server -short -v

# Run full integration tests (requires orchestrators)
go test ./server -run TestWHIPWHEPIntegration -v
```

## Test Data

### Mock SDP Offer

The tests use a realistic SDP offer that includes:
- H.264 video codec (required by go-livepeer)
- Opus audio codec
- Proper ICE and DTLS setup
- Bundle group configuration

### Mock Job Requests

Job requests are created with:
- **Stream ID**: Auto-generated unique identifier
- **Capability**: Either "whip-ingest" or "whep-subscribe"
- **Parameters**: ComfyUI prompts and processing parameters
- **Timeout**: 30 seconds default

## Expected Behavior

### Successful Cases

1. **Direct WHIP**: Returns 201 Created with SDP answer
2. **Job-based WHIP**: Returns 201 Created or 503 Service Unavailable (no orchestrators)
3. **Proper Headers**: Content-Type: application/sdp, Location header set
4. **CORS**: Appropriate CORS headers when enabled

### Error Cases

1. **Invalid Content-Type**: Returns 415 Unsupported Media Type
2. **Missing Stream**: Returns 400 Bad Request
3. **Invalid Job**: Returns 400 Bad Request
4. **No Orchestrators**: Returns 503 Service Unavailable

## Integration with ComfyStream

These tests validate the integration points between go-livepeer and ComfyStream:

1. **WHIP Ingestion**: Stream comes from external client → go-livepeer → ComfyStream
2. **Processing**: ComfyStream applies AI transformations using ComfyUI
3. **WHEP Egress**: Processed stream goes ComfyStream → go-livepeer → external client

## Comparison with Python Client

The Go tests complement the Python `whip_client_example.py`:

| Aspect | Python Client | Go Tests |
|--------|---------------|----------|
| **Purpose** | Real WebRTC client | Unit/integration testing |
| **Media Source** | Actual video files/camera | Mock SDP offers |
| **Server** | External go-livepeer | Test server instances |
| **Validation** | Visual/functional | Automated assertions |

## Usage in CI/CD

### Unit Tests (Fast)
```bash
go test ./server -short -run Test.*WHIP.* -v
```

### Integration Tests (Requires Services)
```bash
# Start ComfyStream
python -m comfystream.server.app &

# Start go-livepeer orchestrator and gateway
./go-livepeer -orchestrator -transcoder &
./go-livepeer -gateway &

# Run integration tests
go test ./server -run TestWHIPWHEPIntegration -v
```

## Debugging

### Common Issues

1. **No orchestrators available**: Expected in test environment without real orchestrators
2. **WHIP disabled**: Ensure `LIVE_AI_WHIP_ADDR` environment variable is set
3. **SDP validation errors**: Check that mock SDP contains required H.264 codec

### Debug Logging

Add debug output to tests:
```go
t.Logf("Response status: %d, body: %s", resp.StatusCode, string(body))
t.Logf("Response headers: %v", resp.Header)
```

## Related Files

- `whip_client_example.py`: Python WebRTC client example
- `ai_mediaserver.go`: WHIP endpoint implementations
- `job_rpc.go`: Job-based WHIP/WHEP handlers
- `media/whip_server.go`: Core WHIP protocol implementation
- `media/whip_connection.go`: WHIP connection management

## Future Enhancements

1. **Real WebRTC**: Integration with Pion WebRTC for actual media flow testing
2. **Performance Tests**: Latency and throughput measurements
3. **Load Tests**: Multiple concurrent WHIP sessions
4. **Security Tests**: Authentication and authorization validation
5. **Codec Tests**: Different video/audio codec combinations 