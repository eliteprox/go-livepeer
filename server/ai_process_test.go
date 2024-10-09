package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/livepeer/go-livepeer/ai/worker"
	lpnet "github.com/livepeer/go-livepeer/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_submitLLM(t *testing.T) {
	type args struct {
		ctx    context.Context
		params aiRequestParams
		sess   *AISession
		req    worker.GenLLMJSONRequestBody
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := submitLLM(tt.args.ctx, tt.args.params, tt.args.sess, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("submitLLM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("submitLLM() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_submitAudioToText(t *testing.T) {
	type args struct {
		ctx    context.Context
		params aiRequestParams
		sess   *AISession
		req    worker.GenAudioToTextMultipartRequestBody
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name: "invalid request (no file)",
			args: args{
				ctx:    context.Background(),
				params: aiRequestParams{},
				sess:   &AISession{},
				req:    worker.GenAudioToTextMultipartRequestBody{},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "nil session",
			args: args{
				ctx:    context.Background(),
				params: aiRequestParams{},
				sess:   nil,
				req:    worker.GenAudioToTextMultipartRequestBody{},
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := submitAudioToText(tt.args.ctx, tt.args.params, tt.args.sess, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("submitAudioToText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("submitAudioToText() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodeReqMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		want     string
	}{
		{
			name: "valid metadata",
			metadata: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			want: `{"key1":"value1","key2":"value2"}`,
		},
		{
			name:     "empty metadata",
			metadata: map[string]string{},
			want:     `{}`,
		},
		{
			name:     "nil metadata",
			metadata: nil,
			want:     `null`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeReqMetadata(tt.metadata)
			if got != tt.want {
				t.Errorf("encodeReqMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isNoCapacityError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "insufficient capacity error",
			err:  errors.New("Insufficient capacity"),
			want: true,
		},
		{
			name: "INSUFFICIENT capacity ERROR",
			err:  errors.New("Insufficient capacity"),
			want: true,
		},
		{
			name: "non-insufficient capacity error",
			err:  errors.New("some other error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNoCapacityError(tt.err); got != tt.want {
				t.Errorf("isNoCapacityError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isInvalidTicketSenderNonc(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "invalid ticket sendernonce",
			err:  errors.New("invalid ticket sendernonce"),
			want: true,
		},
		{
			name: "INVALID ticket sendernonce",
			err:  errors.New("Invalid ticket sendernonce"),
			want: true,
		},
		{
			name: "non-insufficient capacity error",
			err:  errors.New("some other error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInvalidTicketSenderNonce(tt.err); got != tt.want {
				t.Errorf("isNoCapacityError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isRetryableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ticketparams expired",
			err:  errors.New("ticketparams expired"),
			want: true,
		},
		{
			name: "TICKETPARAMS expired",
			err:  errors.New("TICKETPARAMS expired"),
			want: true,
		},
		{
			name: "non-retryable error",
			err:  errors.New("some other error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryableError(tt.err); got != tt.want {
				t.Errorf("isRetryableError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// makeTestSession returns a minimal AISession suitable for unit tests.
func makeTestSession(orchURL string) *AISession {
	return &AISession{
		BroadcastSession: &BroadcastSession{
			lock:             &sync.RWMutex{},
			OrchestratorInfo: &lpnet.OrchestratorInfo{Transcoder: orchURL},
		},
	}
}

func TestBatchAIRequestErrorType(t *testing.T) {
	// background context: not cancelled, not deadline exceeded
	bgCtx := context.Background()

	// cancelled context simulating a processing timeout
	deadlineCtx, cancelDeadline := context.WithTimeout(bgCtx, time.Millisecond)
	defer cancelDeadline()
	// let it expire
	<-deadlineCtx.Done()

	tests := []struct {
		name   string
		retErr error
		cctx   context.Context
		want   string
	}{
		{"nil error → success", nil, bgCtx, ""},
		{"bad request error", &BadRequestError{err: errors.New("too large")}, bgCtx, "bad_request"},
		{"wrapped bad request", fmt.Errorf("outer: %w", &BadRequestError{err: errors.New("x")}), bgCtx, "bad_request"},
		{"service unavailable, no timeout → no_orchestrators", &ServiceUnavailableError{err: errors.New("none")}, bgCtx, "no_orchestrators"},
		{"service unavailable, deadline exceeded → timeout", &ServiceUnavailableError{err: errors.New("expired")}, deadlineCtx, "timeout"},
		{"generic error → worker_error", errors.New("some unexpected error"), bgCtx, "worker_error"},
		{"nil cctx → no_orchestrators not panic", &ServiceUnavailableError{err: errors.New("x")}, nil, "no_orchestrators"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := batchAIRequestErrorType(tt.retErr, tt.cctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHandleNonStreamingResponse_SuccessFields(t *testing.T) {
	finishReason := "stop"
	body := `{
		"id": "cmpl-abc123",
		"model": "llama-3.1-8B-Instruct",
		"choices": [{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],
		"usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
		"created": 12345
	}`

	maxTokens := 50
	modelID := "llama-3.1-8B-Instruct"
	req := worker.GenLLMJSONRequestBody{
		Model:     &modelID,
		MaxTokens: &maxTokens,
	}
	sess := makeTestSession("http://orch:8935")

	res, err := handleNonStreamingResponse(
		context.Background(), "tok-test",
		io.NopCloser(strings.NewReader(body)),
		sess, req, time.Now(),
	)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "cmpl-abc123", res.Id)
	assert.Equal(t, "llama-3.1-8B-Instruct", res.Model)
	assert.Equal(t, 10, res.Usage.PromptTokens)
	assert.Equal(t, 20, res.Usage.CompletionTokens)
	assert.Equal(t, 30, res.Usage.TotalTokens)
	require.Len(t, res.Choices, 1)
	require.NotNil(t, res.Choices[0].FinishReason)
	assert.Equal(t, finishReason, *res.Choices[0].FinishReason)
}

func TestHandleNonStreamingResponse_InvalidJSON(t *testing.T) {
	maxTokens := 50
	modelID := "llama-3.1-8B-Instruct"
	req := worker.GenLLMJSONRequestBody{Model: &modelID, MaxTokens: &maxTokens}
	sess := makeTestSession("http://orch:8935")

	res, err := handleNonStreamingResponse(
		context.Background(), "tok-test",
		io.NopCloser(strings.NewReader("{not valid json")),
		sess, req, time.Now(),
	)

	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestHandleSSEStream_DeliversChunks(t *testing.T) {
	r, w := io.Pipe()

	go func() {
		defer w.Close()
		// first chunk — content, no finish_reason
		fmt.Fprintf(w, "data: {\"id\":\"cmpl-1\",\"model\":\"llama-3.1-8B\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"},\"finish_reason\":null}],\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0},\"created\":1}\n\n")
		// final chunk — finish_reason = stop, usage populated
		fmt.Fprintf(w, "data: {\"id\":\"cmpl-1\",\"model\":\"llama-3.1-8B\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15},\"created\":1}\n\n")
	}()

	maxTokens := 50
	modelID := "llama-3.1-8B"
	streaming := true
	req := worker.GenLLMJSONRequestBody{
		Model:     &modelID,
		MaxTokens: &maxTokens,
		Stream:    &streaming,
	}
	sess := makeTestSession("http://orch:8935")

	ch, err := handleSSEStream(context.Background(), "tok-test", r, sess, req, time.Now())
	require.NoError(t, err)
	require.NotNil(t, ch)

	var chunks []*worker.LLMResponse
	for chunk := range ch {
		chunks = append(chunks, chunk)
	}

	require.Len(t, chunks, 2)
	assert.Equal(t, "cmpl-1", chunks[0].Id)
	// final chunk has usage populated
	assert.Equal(t, 10, chunks[1].Usage.PromptTokens)
	assert.Equal(t, 5, chunks[1].Usage.CompletionTokens)
}

func TestHandleSSEStream_EmptyBody(t *testing.T) {
	maxTokens := 50
	modelID := "llama-3.1-8B"
	req := worker.GenLLMJSONRequestBody{Model: &modelID, MaxTokens: &maxTokens}
	sess := makeTestSession("http://orch:8935")

	ch, err := handleSSEStream(context.Background(), "tok-test", io.NopCloser(strings.NewReader("")), sess, req, time.Now())
	require.NoError(t, err)

	var chunks []*worker.LLMResponse
	for chunk := range ch {
		chunks = append(chunks, chunk)
	}
	assert.Empty(t, chunks)
}

func TestHandleSSEStream_SkipsMalformedLines(t *testing.T) {
	r, w := io.Pipe()
	go func() {
		defer w.Close()
		fmt.Fprintf(w, "not-a-data-line\n")
		fmt.Fprintf(w, "data: {bad json}\n\n")
		fmt.Fprintf(w, "data: {\"id\":\"ok\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2},\"created\":1}\n\n")
	}()

	maxTokens := 50
	modelID := "m"
	req := worker.GenLLMJSONRequestBody{Model: &modelID, MaxTokens: &maxTokens}
	sess := makeTestSession("http://orch:8935")

	ch, err := handleSSEStream(context.Background(), "tok-test", r, sess, req, time.Now())
	require.NoError(t, err)

	var chunks []*worker.LLMResponse
	for chunk := range ch {
		chunks = append(chunks, chunk)
	}
	require.Len(t, chunks, 1)
	assert.Equal(t, "ok", chunks[0].Id)
}
