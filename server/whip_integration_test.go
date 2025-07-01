package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/media"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock SDP offer for testing
const mockSDPOffer = `v=0
o=- 123456789 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=msid-semantic: WMS
m=video 54400 UDP/TLS/RTP/SAVPF 96 100
c=IN IP4 127.0.0.1
a=rtcp:9 IN IP4 127.0.0.1
a=ice-ufrag:test123
a=ice-pwd:testpassword123
a=ice-options:trickle
a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF
a=setup:actpass
a=mid:0
a=sendonly
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtpmap:100 H264/90000
a=rtcp-fb:100 goog-remb
a=rtcp-fb:100 transport-cc
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 nack
a=rtcp-fb:100 nack pli
a=fmtp:100 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
a=ssrc-group:FID 1234567890 1234567891
a=ssrc:1234567890 cname:test-stream
a=ssrc:1234567890 msid:test-stream video0
a=ssrc:1234567891 cname:test-stream
a=ssrc:1234567891 msid:test-stream video0
m=audio 54401 UDP/TLS/RTP/SAVPF 111
c=IN IP4 127.0.0.1
a=rtcp:9 IN IP4 127.0.0.1
a=ice-ufrag:test123
a=ice-pwd:testpassword123
a=ice-options:trickle
a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF
a=setup:actpass
a=mid:1
a=sendonly
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=ssrc:1234567892 cname:test-stream
a=ssrc:1234567892 msid:test-stream audio0`

// Mock job request for testing
func createMockJobRequest(capability, streamID string) *JobRequest {
	jobRequestDetails := &JobRequestDetails{
		StartStream:       capability == "whip-ingest",
		StartStreamOutput: capability == "whep-subscribe",
		StreamID:          streamID,
	}

	requestData, _ := json.Marshal(jobRequestDetails)

	return &JobRequest{
		ID:         fmt.Sprintf("test-job-%d", time.Now().UnixNano()),
		Request:    string(requestData),
		Parameters: `{"prompts": [{"text": "test prompt"}], "width": 512, "height": 512}`,
		Capability: capability,
		Timeout:    30,
	}
}

// TestDirectWHIPEndpoint tests the direct WHIP endpoint setup and compilation
func TestDirectWHIPEndpoint(t *testing.T) {
	// Set environment variable to enable WHIP with a dynamic port
	testPort := ":0" // Use port 0 to let system assign an available port
	os.Setenv("LIVE_AI_WHIP_ADDR", testPort)
	defer os.Unsetenv("LIVE_AI_WHIP_ADDR")

	// Create test server
	ls := setupServer(t)

	t.Run("WHIPServerCreation", func(t *testing.T) {
		// Test that WHIP server can be created without errors
		whipServer := media.NewWHIPServer()
		assert.NotNil(t, whipServer, "WHIP server should be created successfully")
	})

	t.Run("WHIPHandlerCreation", func(t *testing.T) {
		// Test that WHIP handler can be created without errors
		whipServer := media.NewWHIPServer()
		handler := ls.CreateWhip(whipServer)
		assert.NotNil(t, handler, "WHIP handler should be created successfully")
	})

	t.Run("WHIPRouteRegistration", func(t *testing.T) {
		// Test that WHIP route can be registered without errors
		whipServer := media.NewWHIPServer()

		// This should not panic during registration
		assert.NotPanics(t, func() {
			ls.HTTPMux.Handle("POST /live/video-to-video/{stream}/whip", ls.CreateWhip(whipServer))
		}, "WHIP route registration should not panic")
	})

	// Note: Full integration tests require a complete server environment with CGO/CUDA setup
	// as specified in launch.json. These tests verify that the WHIP components can be
	// created and registered without compilation errors.
}

// TestJobBasedWHIPEndpoint tests the job-based WHIP endpoint basic functionality
func TestJobBasedWHIPEndpoint(t *testing.T) {
	// Create test server
	ls := setupServer(t)

	// Create handler
	handler := ls.SubmitJob()

	t.Run("SubmitJobHandlerCreation", func(t *testing.T) {
		// Test that the submit job handler can be created
		assert.NotNil(t, handler, "SubmitJob handler should be created successfully")
	})

	t.Run("JobRequestParsing", func(t *testing.T) {
		// Test that job requests can be created and marshaled properly
		streamID := "test-stream-" + string(core.RandomManifestID())
		jobReq := createMockJobRequest("whip-ingest", streamID)

		// Should be able to marshal the job request
		jobReqData, err := json.Marshal(jobReq)
		require.NoError(t, err)
		assert.NotEmpty(t, jobReqData)

		// Should be able to base64 encode it
		jobReqHeader := base64.StdEncoding.EncodeToString(jobReqData)
		assert.NotEmpty(t, jobReqHeader)
	})

	t.Run("MissingJobRequest", func(t *testing.T) {
		// Test with missing job request header - this should fail early
		req := httptest.NewRequest("POST", "/process/request/whip-ingest", strings.NewReader(mockSDPOffer))
		req.Header.Set("Content-Type", "application/sdp")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		// Should return 400 for missing job request header
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("InvalidJobRequest", func(t *testing.T) {
		// Test with invalid job request header - this should fail early
		req := httptest.NewRequest("POST", "/process/request/whip-ingest", strings.NewReader(mockSDPOffer))
		req.Header.Set("Content-Type", "application/sdp")
		req.Header.Set("Livepeer", "invalid-base64")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		// Should return 400 for invalid base64
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	// Note: Full WHIP/WHEP job processing requires orchestrator setup and complete
	// server environment as specified in launch.json. These tests verify basic
	// job request handling and validation.
}

// TestWHIPWHEPIntegration tests the basic WHIP/WHEP concepts
func TestWHIPWHEPIntegration(t *testing.T) {
	// Skip this test if we don't have orchestrators available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	streamID := "integration-test-" + string(core.RandomManifestID())

	t.Run("JobRequestCreation", func(t *testing.T) {
		// Test that we can create job requests for both WHIP and WHEP
		whipJobReq := createMockJobRequest("whip-ingest", streamID)
		whepJobReq := createMockJobRequest("whep-subscribe", streamID)

		// Verify WHIP job request
		assert.Equal(t, "whip-ingest", whipJobReq.Capability)
		assert.Contains(t, whipJobReq.Request, `"start_stream":true`)
		assert.Contains(t, whipJobReq.Request, streamID)

		// Verify WHEP job request
		assert.Equal(t, "whep-subscribe", whepJobReq.Capability)
		assert.Contains(t, whepJobReq.Request, `"start_stream_output":true`)
		assert.Contains(t, whepJobReq.Request, streamID)
	})

	t.Run("JobRequestSerialization", func(t *testing.T) {
		// Test that job requests can be properly serialized
		whipJobReq := createMockJobRequest("whip-ingest", streamID)

		// Should be able to marshal to JSON
		jobData, err := json.Marshal(whipJobReq)
		require.NoError(t, err)
		assert.NotEmpty(t, jobData)

		// Should be able to base64 encode
		jobHeader := base64.StdEncoding.EncodeToString(jobData)
		assert.NotEmpty(t, jobHeader)

		// Should be able to decode back
		decodedData, err := base64.StdEncoding.DecodeString(jobHeader)
		require.NoError(t, err)

		var decodedJobReq JobRequest
		err = json.Unmarshal(decodedData, &decodedJobReq)
		require.NoError(t, err)
		assert.Equal(t, whipJobReq.Capability, decodedJobReq.Capability)
	})

	// Note: Full WHIP->WHEP integration requires orchestrator setup and complete
	// server environment as specified in launch.json. These tests verify the
	// basic job request structures and serialization used in WHIP/WHEP workflows.
}

// TestWHIPEndpointRouting tests basic endpoint routing setup
func TestWHIPEndpointRouting(t *testing.T) {
	// Create test server
	ls := setupServer(t)

	t.Run("SubmitJobHandlerCreation", func(t *testing.T) {
		// Test that SubmitJob handler can be created
		submitJobHandler := ls.SubmitJob()
		assert.NotNil(t, submitJobHandler, "SubmitJob handler should be created")
	})

	t.Run("HTTPMuxConfiguration", func(t *testing.T) {
		// Test that routes can be registered without errors
		mux := http.NewServeMux()

		// Should be able to register the submit job route
		assert.NotPanics(t, func() {
			mux.Handle("/process/request/", ls.SubmitJob())
		}, "SubmitJob route registration should not panic")
	})

	t.Run("NonExistentRouteHandling", func(t *testing.T) {
		// Test that non-existent routes return 404
		mux := http.NewServeMux()
		req := httptest.NewRequest("POST", "/non-existent-route", strings.NewReader("test"))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		// Should return 404 for non-existent routes
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	// Note: Full endpoint testing requires complete server environment as specified
	// in launch.json. These tests verify basic handler creation and route registration.
}

// Helper function to setup a test server
func setupServer(t *testing.T) *LivepeerServer {
	// Create a test node
	workDir := t.TempDir()
	node := &core.LivepeerNode{
		WorkDir:       workDir,
		LiveMu:        &sync.RWMutex{},
		LivePipelines: make(map[string]*core.LivePipeline),
		ExternalCapabilities: &core.ExternalCapabilities{
			Streams: make(map[string]*core.StreamData),
		},
	}

	// Create test server
	ls := &LivepeerServer{
		LivepeerNode: node,
		HTTPMux:      http.NewServeMux(),
	}

	return ls
}

// TestWHIPClientExample demonstrates how to use WHIP with the example client
func TestWHIPClientExample(t *testing.T) {
	t.Run("DocumentationExample", func(t *testing.T) {
		// This test documents how to use the WHIP client programmatically
		// Similar to the Python whip_client_example.py

		// Example of creating a WHIP request
		streamName := "test-stream"
		whipURL := fmt.Sprintf("http://localhost:8937/live/video-to-video/%s/whip", streamName)

		// Create SDP offer (in real usage, this would come from WebRTC)
		sdpOffer := mockSDPOffer

		// Create HTTP request
		req, err := http.NewRequest("POST", whipURL, strings.NewReader(sdpOffer))
		require.NoError(t, err)

		req.Header.Set("Content-Type", "application/sdp")
		req.Header.Set("User-Agent", "Go-WHIP-Client/1.0")

		// Add query parameters for ComfyUI prompts
		q := req.URL.Query()
		q.Add("pipeline", "comfyui")
		q.Add("params", `{"prompt": "test prompt for AI processing"}`)
		req.URL.RawQuery = q.Encode()

		// In a real test, you would send this request to a running server
		// For documentation purposes, we just verify the request is well-formed
		assert.Equal(t, "application/sdp", req.Header.Get("Content-Type"))
		assert.Contains(t, req.URL.String(), "pipeline=comfyui")
		assert.Contains(t, req.URL.String(), "params=")

		t.Logf("Example WHIP request URL: %s", req.URL.String())
		t.Logf("Example WHIP request headers: %v", req.Header)
	})
}
