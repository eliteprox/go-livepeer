package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/livepeer/go-livepeer/ai/worker"
	"github.com/livepeer/go-livepeer/clog"
	"github.com/livepeer/go-livepeer/core"
	"github.com/stretchr/testify/require"
)

type recordingIngester struct {
	mu      sync.Mutex
	subject string
	report  LLMUsageReport
	err     error
	calls   int
}

func (r *recordingIngester) Ingest(_ context.Context, subject string, report LLMUsageReport) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.subject = subject
	r.report = report
	return r.err
}

func TestLLMUsageReportValidate(t *testing.T) {
	valid := LLMUsageReport{
		RequestID:      "req-1",
		Provider:       "gemini",
		Model:          "gemini-2.5-flash",
		InputTokens:    3,
		OutputTokens:   5,
		CredentialMode: LLMCredentialManaged,
		Route:          LLMUsageRouteLLMChat,
	}
	require.NoError(t, valid.Validate())

	cases := []LLMUsageReport{
		{Provider: "gemini", Model: "m", CredentialMode: LLMCredentialManaged, Route: "/llm"},
		{RequestID: "req:1", Provider: "gemini", Model: "m", CredentialMode: LLMCredentialManaged, Route: "/llm"},
		{RequestID: "req-1", Model: "m", CredentialMode: LLMCredentialManaged, Route: "/llm"},
		{RequestID: "req-1", Provider: "gemini", CredentialMode: LLMCredentialManaged, Route: "/llm"},
		{RequestID: "req-1", Provider: "gemini", Model: "m", InputTokens: -1, CredentialMode: LLMCredentialManaged, Route: "/llm"},
		{RequestID: "req-1", Provider: "gemini", Model: "m", CredentialMode: "other", Route: "/llm"},
		{RequestID: "req-1", Provider: "gemini", Model: "m", CredentialMode: LLMCredentialManaged},
	}
	for _, report := range cases {
		require.Error(t, report.Validate())
	}
}

func TestLLMUsageCloudEventsDeterministicIDs(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	events := llmUsageCloudEvents("auth-1", "livepeer-remote-signer", LLMUsageReport{
		RequestID:      "req-1",
		Provider:       "gemini",
		Model:          "gemini-2.5-flash",
		InputTokens:    11,
		OutputTokens:   7,
		CredentialMode: LLMCredentialBYOK,
		Route:          LLMUsageRouteLLMChat,
	}, now)
	require.Len(t, events, 2)
	require.Equal(t, "req-1:input", events[0].ID)
	require.Equal(t, "req-1:output", events[1].ID)
	require.Equal(t, "auth-1", events[0].Subject)
	require.Equal(t, LLMUsageEventType, events[0].Type)
	require.Equal(t, "11", events[0].Data.Tokens)
	require.Equal(t, "7", events[1].Data.Tokens)
	require.Equal(t, LLMUsageTokenTypeInput, events[0].Data.Type)
	require.Equal(t, LLMUsageTokenTypeOutput, events[1].Data.Type)
	require.Equal(t, LLMCredentialBYOK, events[0].Data.CredentialMode)
}

func TestReportLLMUsage_AuthDerivedSubjectAndRejectsSpoofedPayload(t *testing.T) {
	ingester := &recordingIngester{}
	node, err := core.NewLivepeerNode(nil, "", nil)
	require.NoError(t, err)
	ls := &LivepeerServer{LivepeerNode: node, llmUsageIngester: ingester}

	body, err := json.Marshal(LLMUsageReport{
		RequestID:      "req-9",
		Provider:       "gemini",
		Model:          "gemini-2.5-flash",
		InputTokens:    4,
		OutputTokens:   2,
		CredentialMode: LLMCredentialManaged,
		Route:          LLMUsageRouteLLM,
	})
	require.NoError(t, err)

	t.Run("missing identity", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, llmUsageReportPath, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		ls.ReportLLMUsage(rr, req)
		require.Equal(t, http.StatusUnauthorized, rr.Code)
		require.Equal(t, 0, ingester.calls)
	})

	t.Run("header auth id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, llmUsageReportPath, bytes.NewReader(body))
		req.Header.Set(remoteSignerAuthIDHeader, "user-42")
		rr := httptest.NewRecorder()
		ls.ReportLLMUsage(rr, req)
		require.Equal(t, http.StatusNoContent, rr.Code)
		require.Equal(t, 1, ingester.calls)
		require.Equal(t, "user-42", ingester.subject)
		require.Equal(t, "req-9", ingester.report.RequestID)
	})

	t.Run("webhook auth id wins over header", func(t *testing.T) {
		webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Empty(t, r.Header.Get(llmProviderAPIKeyHeader))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":200,"auth_id":"webhook-user"}`))
		}))
		defer webhook.Close()
		webhookURL, err := url.Parse(webhook.URL)
		require.NoError(t, err)
		node.RemoteSignerWebhookURL = webhookURL

		req := httptest.NewRequest(http.MethodPost, llmUsageReportPath, bytes.NewReader(body))
		req.Header.Set(remoteSignerAuthIDHeader, "spoofed")
		req.Header.Set(llmProviderAPIKeyHeader, "should-not-be-required")
		rr := httptest.NewRecorder()
		ls.ReportLLMUsage(rr, req)
		require.Equal(t, http.StatusNoContent, rr.Code)
		require.Equal(t, "webhook-user", ingester.subject)
	})

	t.Run("malformed payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, llmUsageReportPath, strings.NewReader(`{"request_id":"bad:id","provider":"gemini","model":"m","input_tokens":1,"output_tokens":1,"credential_mode":"managed","route":"/llm"}`))
		req.Header.Set(remoteSignerAuthIDHeader, "user-42")
		rr := httptest.NewRecorder()
		ls.ReportLLMUsage(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestReportLLMUsage_OpenMeterFailure(t *testing.T) {
	ingester := &recordingIngester{err: errors.New("boom")}
	node, err := core.NewLivepeerNode(nil, "", nil)
	require.NoError(t, err)
	ls := &LivepeerServer{LivepeerNode: node, llmUsageIngester: ingester}

	body, err := json.Marshal(LLMUsageReport{
		RequestID:      "req-err",
		Provider:       "gemini",
		Model:          "gemini-2.5-flash",
		CredentialMode: LLMCredentialManaged,
		Route:          LLMUsageRouteLLM,
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, llmUsageReportPath, bytes.NewReader(body))
	req.Header.Set(remoteSignerAuthIDHeader, "user-42")
	rr := httptest.NewRecorder()
	ls.ReportLLMUsage(rr, req)
	require.Equal(t, http.StatusBadGateway, rr.Code)
}

func TestLlmSignerHeadersFromRequestOmitsProviderKey(t *testing.T) {
	node, err := core.NewLivepeerNode(nil, "", nil)
	require.NoError(t, err)
	node.RemoteSignerHeaders = map[string]string{"Authorization": "Bearer gateway"}
	req := httptest.NewRequest(http.MethodPost, "/llm", nil)
	req.Header.Set("Authorization", "Bearer user-key")
	req.Header.Set(llmProviderAPIKeyHeader, "sk-provider-secret")
	req.Header.Set(remoteSignerAuthIDHeader, "auth-1")
	headers := llmSignerHeadersFromRequest(req, node)
	require.Equal(t, "Bearer user-key", headers["Authorization"])
	require.Equal(t, "auth-1", headers[remoteSignerAuthIDHeader])
	_, ok := headers[llmProviderAPIKeyHeader]
	require.False(t, ok)
}

func TestHandleNonStreamingResponse_ReportsUsage(t *testing.T) {
	reported := make(chan LLMUsageReport, 1)
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, llmUsageReportPath, r.URL.Path)
		require.Equal(t, "Bearer user-key", r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get(llmProviderAPIKeyHeader))
		var report LLMUsageReport
		require.NoError(t, json.NewDecoder(r.Body).Decode(&report))
		reported <- report
		w.WriteHeader(http.StatusNoContent)
	}))
	defer signer.Close()
	signerURL, err := url.Parse(signer.URL)
	require.NoError(t, err)
	node, err := core.NewLivepeerNode(nil, "", nil)
	require.NoError(t, err)
	node.RemoteSignerUrl = signerURL

	model := "gemini-2.5-flash"
	body, err := json.Marshal(worker.LLMResponse{
		Usage: worker.LLMTokenUsage{PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18},
	})
	require.NoError(t, err)
	ctx := clog.AddVal(context.Background(), "request_id", "req-1")
	sess := &AISession{BroadcastSession: &BroadcastSession{}}
	params := aiRequestParams{
		node:             node,
		llmSignerHeaders: map[string]string{"Authorization": "Bearer user-key", llmProviderAPIKeyHeader: "secret"},
	}
	got, err := handleNonStreamingResponse(ctx, io.NopCloser(bytes.NewReader(body)), sess, worker.GenLLMJSONRequestBody{Model: &model}, time.Now(), params)
	require.NoError(t, err)
	require.Equal(t, 11, got.Usage.PromptTokens)

	select {
	case report := <-reported:
		require.Equal(t, "req-1", report.RequestID)
		require.Equal(t, 11, report.InputTokens)
		require.Equal(t, 7, report.OutputTokens)
		require.Equal(t, LLMCredentialManaged, report.CredentialMode)
		require.Equal(t, LLMUsageRouteLLM, report.Route)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for usage report")
	}
}

func TestHandleSSEStream_ReportsFinalUsageAndMissingUsage(t *testing.T) {
	model := "gemini-2.5-flash"
	sess := &AISession{BroadcastSession: &BroadcastSession{}}

	t.Run("reports final usage", func(t *testing.T) {
		reported := make(chan LLMUsageReport, 1)
		signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var report LLMUsageReport
			require.NoError(t, json.NewDecoder(r.Body).Decode(&report))
			reported <- report
			w.WriteHeader(http.StatusNoContent)
		}))
		defer signer.Close()
		signerURL, err := url.Parse(signer.URL)
		require.NoError(t, err)
		node, err := core.NewLivepeerNode(nil, "", nil)
		require.NoError(t, err)
		node.RemoteSignerUrl = signerURL

		stop := "stop"
		chunk1, _ := json.Marshal(worker.LLMResponse{Choices: []worker.LLMChoice{{FinishReason: nil}}, Usage: worker.LLMTokenUsage{}})
		chunk2, _ := json.Marshal(worker.LLMResponse{
			Choices: []worker.LLMChoice{{FinishReason: &stop}},
			Usage:   worker.LLMTokenUsage{PromptTokens: 9, CompletionTokens: 4, TotalTokens: 13},
		})
		sse := "data: " + string(chunk1) + "\n\ndata: " + string(chunk2) + "\n"
		ctx := clog.AddVal(context.Background(), "request_id", "stream-1")
		ch, err := handleSSEStream(ctx, io.NopCloser(strings.NewReader(sse)), sess, worker.GenLLMJSONRequestBody{Model: &model}, time.Now(), aiRequestParams{node: node})
		require.NoError(t, err)
		for range ch {
		}
		select {
		case report := <-reported:
			require.Equal(t, 9, report.InputTokens)
			require.Equal(t, 4, report.OutputTokens)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for streaming usage report")
		}
	})

	t.Run("missing final usage does not report zeros as success", func(t *testing.T) {
		called := make(chan struct{}, 1)
		signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer signer.Close()
		signerURL, err := url.Parse(signer.URL)
		require.NoError(t, err)
		node, err := core.NewLivepeerNode(nil, "", nil)
		require.NoError(t, err)
		node.RemoteSignerUrl = signerURL

		ch, err := handleSSEStream(context.Background(), io.NopCloser(strings.NewReader("not-sse\n")), sess, worker.GenLLMJSONRequestBody{Model: &model}, time.Now(), aiRequestParams{node: node})
		require.NoError(t, err)
		for range ch {
		}
		select {
		case <-called:
			t.Fatal("reported usage for a stream that never sent usage")
		case <-time.After(200 * time.Millisecond):
		}
	})
}
