package byoc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/livepeer/go-livepeer/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrchEventTopic(t *testing.T) {
	tests := []struct {
		eventType string
		want      string
	}{
		{"job_credential_verify_result", "job_auth"},
		{"job_orchestrator_received", "job_orchestrator"},
		{"job_orchestrator_worker_result", "job_orchestrator"},
		{"job_orchestrator_capacity_rejected", "job_orchestrator"},
		{"payment_compute_charged", "job_payment"},
		{"payment_insufficient_balance", "job_payment"},
		{"unknown_event", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			assert.Equal(t, tt.want, orchEventTopic(tt.eventType))
		})
	}
}

// testOrchToken builds a minimal JobToken pointing at the given service URL with zero price.
func testOrchToken(serviceAddr string) JobToken {
	return JobToken{
		ServiceAddr: serviceAddr,
		Price:       &net.PriceInfo{PricePerUnit: 0, PixelsPerUnit: 1},
		TicketParams: &net.TicketParams{
			Recipient: ethcommon.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
		},
	}
}

// TestSendJobToOrch_XLivepeerEventsHeaderGraceful verifies that sendJobToOrch
// does not fail regardless of whether X-Livepeer-Events is absent, valid, or
// malformed JSON.
func TestSendJobToOrch_XLivepeerEventsHeaderGraceful(t *testing.T) {
	orchEvents := []struct {
		Type string                 `json:"type"`
		Data map[string]interface{} `json:"data"`
	}{
		{Type: "job_orchestrator_received", Data: map[string]interface{}{"request_id": "req-1"}},
	}
	eventsJSON, err := json.Marshal(orchEvents)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"valid_header", string(eventsJSON)},
		{"no_header", ""},
		{"malformed_json", "{not valid json}"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.header != "" {
					w.Header().Set("X-Livepeer-Events", tc.header)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{}`))
			}))
			defer ts.Close()

			bsg := &BYOCGatewayServer{node: mockJobLivepeerNode()}
			jobReq := &JobRequest{
				ID:         "test-req",
				Capability: "test-cap",
				Sender:     "0x0000000000000000000000000000000000000000",
				Timeout:    5,
			}
			orchToken := testOrchToken(ts.URL)

			resp, code, err := bsg.sendJobToOrch(context.Background(), nil, jobReq, "", orchToken, "/process/request/test", []byte(`{}`))
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, code)
			resp.Body.Close()
		})
	}
}
