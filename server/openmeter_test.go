package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpenMeterClient_RetriesThenSucceeds(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "application/cloudevents+json", r.Header.Get("Content-Type"))
		require.Equal(t, "Bearer secret-token", r.Header.Get("Authorization"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var event llmUsageCloudEvent
		require.NoError(t, json.Unmarshal(body, &event))
		require.NotContains(t, string(body), "secret-token")
		n := attempts.Add(1)
		if n == 1 || n == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := newOpenMeterClient(srv.URL, "secret-token", "livepeer-remote-signer")
	client.sleep = func(time.Duration) {}
	err := client.Ingest(context.Background(), "user-1", LLMUsageReport{
		RequestID:      "req-retry",
		Provider:       "gemini",
		Model:          "gemini-2.5-flash",
		InputTokens:    1,
		OutputTokens:   2,
		CredentialMode: LLMCredentialManaged,
		Route:          LLMUsageRouteLLMChat,
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, attempts.Load(), int32(3))
}

func TestOpenMeterClient_DoesNotRetryClientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := newOpenMeterClient(srv.URL, "secret-token", "src")
	client.sleep = func(time.Duration) {}
	err := client.Ingest(context.Background(), "user-1", LLMUsageReport{
		RequestID:      "req-401",
		Provider:       "gemini",
		Model:          "gemini-2.5-flash",
		CredentialMode: LLMCredentialManaged,
		Route:          LLMUsageRouteLLM,
	})
	require.Error(t, err)
	require.Equal(t, int32(1), attempts.Load())
}
