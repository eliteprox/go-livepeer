package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/livepeer/go-livepeer/ai/worker"
	"github.com/livepeer/go-livepeer/clog"
	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/monitor"
)

const (
	LLMUsageEventType       = "llm_tokens"
	LLMCredentialManaged    = "managed"
	LLMCredentialBYOK       = "byok"
	LLMUsageTokenTypeInput  = "input"
	LLMUsageTokenTypeOutput = "output"
	LLMUsageRouteLLM        = "/llm"
	LLMUsageRouteLLMChat    = "/llm/chat"
	defaultOpenMeterSource  = "livepeer-remote-signer"
	maxLLMUsageFieldLen     = 128
	maxLLMUsageTokens       = 100_000_000
	llmProviderAPIKeyHeader = "X-Provider-API-Key"
	llmCredentialModeHeader = "X-LLM-Credential-Mode"
	llmUsageReportPath      = "/report-llm-usage"
	llmUsageReportTimeout   = 10 * time.Second
)

// LLMUsageReport is the authenticated usage payload sent to the remote signer.
// Callers must not include a billing subject; the signer derives it from auth.
type LLMUsageReport struct {
	RequestID      string `json:"request_id"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	InputTokens    int    `json:"input_tokens"`
	OutputTokens   int    `json:"output_tokens"`
	CredentialMode string `json:"credential_mode"`
	Route          string `json:"route"`
}

type llmUsageCloudEvent struct {
	SpecVersion string            `json:"specversion"`
	ID          string            `json:"id"`
	Source      string            `json:"source"`
	Type        string            `json:"type"`
	Subject     string            `json:"subject"`
	Time        time.Time         `json:"time"`
	Data        llmUsageEventData `json:"data"`
}

type llmUsageEventData struct {
	Tokens         string `json:"tokens"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	Type           string `json:"type"`
	CredentialMode string `json:"credential_mode"`
	Route          string `json:"route"`
}

type LLMUsageIngester interface {
	Ingest(ctx context.Context, subject string, report LLMUsageReport) error
}

var llmUsageReportClient = &http.Client{Timeout: llmUsageReportTimeout}

func (r LLMUsageReport) Validate() error {
	if err := validateLLMUsageField("request_id", r.RequestID); err != nil {
		return err
	}
	if strings.Contains(r.RequestID, ":") {
		return errors.New("request_id must not contain ':'")
	}
	if err := validateLLMUsageField("provider", r.Provider); err != nil {
		return err
	}
	if err := validateLLMUsageField("model", r.Model); err != nil {
		return err
	}
	if err := validateLLMUsageField("route", r.Route); err != nil {
		return err
	}
	if r.InputTokens < 0 || r.OutputTokens < 0 {
		return errors.New("token counts must be non-negative")
	}
	if r.InputTokens > maxLLMUsageTokens || r.OutputTokens > maxLLMUsageTokens {
		return errors.New("token counts exceed maximum")
	}
	switch r.CredentialMode {
	case LLMCredentialManaged, LLMCredentialBYOK:
	default:
		return errors.New("credential_mode must be managed or byok")
	}
	return nil
}

func validateLLMUsageField(name, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%s is required", name)
	}
	if trimmed != value {
		return fmt.Errorf("%s must not have leading or trailing whitespace", name)
	}
	if len(value) > maxLLMUsageFieldLen {
		return fmt.Errorf("%s is too long", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", name)
		}
	}
	return nil
}

func llmUsageCloudEvents(subject, source string, report LLMUsageReport, now time.Time) []llmUsageCloudEvent {
	if source == "" {
		source = defaultOpenMeterSource
	}
	mk := func(tokenType string, tokens int) llmUsageCloudEvent {
		return llmUsageCloudEvent{
			SpecVersion: "1.0",
			ID:          report.RequestID + ":" + tokenType,
			Source:      source,
			Type:        LLMUsageEventType,
			Subject:     subject,
			Time:        now,
			Data: llmUsageEventData{
				Tokens:         strconv.Itoa(tokens),
				Provider:       report.Provider,
				Model:          report.Model,
				Type:           tokenType,
				CredentialMode: report.CredentialMode,
				Route:          report.Route,
			},
		}
	}
	return []llmUsageCloudEvent{
		mk(LLMUsageTokenTypeInput, report.InputTokens),
		mk(LLMUsageTokenTypeOutput, report.OutputTokens),
	}
}

func llmSignerHeadersFromRequest(r *http.Request, node *core.LivepeerNode) map[string]string {
	headers := map[string]string{}
	if node != nil {
		for k, v := range node.RemoteSignerHeaders {
			headers[k] = v
		}
	}
	if r == nil {
		return headers
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		headers["Authorization"] = auth
	}
	if authID := strings.TrimSpace(r.Header.Get(remoteSignerAuthIDHeader)); authID != "" {
		headers[remoteSignerAuthIDHeader] = authID
	}
	if mode := strings.TrimSpace(r.Header.Get(llmCredentialModeHeader)); mode != "" {
		headers[llmCredentialModeHeader] = mode
	}
	return headers
}

func credentialModeFromHeaders(headers map[string]string) string {
	if headers == nil {
		return LLMCredentialManaged
	}
	mode := strings.ToLower(strings.TrimSpace(headers[llmCredentialModeHeader]))
	if mode == LLMCredentialBYOK {
		return LLMCredentialBYOK
	}
	return LLMCredentialManaged
}

func (ls *LivepeerServer) ReportLLMUsage(w http.ResponseWriter, r *http.Request) {
	requestID := string(core.RandomManifestID())
	ctx := clog.AddVal(r.Context(), "request_id", requestID)
	clog.Info(ctx, "LLM usage report", "ip", getRemoteAddr(r))

	var report LLMUsageReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		respondJsonError(ctx, w, errors.New("invalid llm usage payload"), http.StatusBadRequest)
		return
	}
	if err := report.Validate(); err != nil {
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}
	ctx = clog.AddVal(ctx, "usage_request_id", report.RequestID)

	subject, status, err := ls.resolveLLMUsageSubject(r)
	if err != nil {
		respondJsonError(ctx, w, err, status)
		return
	}
	ctx = clog.AddVal(ctx, "auth_id", subject)

	ingester := ls.llmUsageIngester
	if ingester == nil {
		ingester = ls.openMeterClient()
	}
	if ingester == nil {
		clog.Errorf(ctx, "OpenMeter ingest is not configured")
		monitor.LLMUsageIngestError("not_configured")
		respondJsonError(ctx, w, errors.New("openmeter not configured"), http.StatusServiceUnavailable)
		return
	}
	if err := ingester.Ingest(ctx, subject, report); err != nil {
		clog.Errorf(ctx, "OpenMeter ingest failed err=%q", err)
		monitor.LLMUsageIngestError("ingest_failed")
		respondJsonError(ctx, w, errors.New("openmeter ingest failed"), http.StatusBadGateway)
		return
	}
	monitor.LLMUsageIngested(report.InputTokens, report.OutputTokens)
	w.WriteHeader(http.StatusNoContent)
}

func (ls *LivepeerServer) resolveLLMUsageSubject(r *http.Request) (string, int, error) {
	status, authResp, authErr := ls.authLivePayment(r, nil)
	if status != http.StatusOK {
		if authErr == nil {
			authErr = errors.New("signer auth rejected request")
		}
		return "", status, authErr
	}
	subject := strings.TrimSpace(r.Header.Get(remoteSignerAuthIDHeader))
	if authResp != nil && strings.TrimSpace(authResp.AuthID) != "" {
		subject = strings.TrimSpace(authResp.AuthID)
	}
	if subject == "" {
		return "", http.StatusUnauthorized, errors.New("missing billing identity")
	}
	return subject, http.StatusOK, nil
}

func (ls *LivepeerServer) openMeterClient() LLMUsageIngester {
	if ls == nil || ls.LivepeerNode == nil {
		return nil
	}
	n := ls.LivepeerNode
	if n.OpenMeterIngestURL == nil || n.OpenMeterAPIToken == "" {
		return nil
	}
	source := n.OpenMeterEventSource
	if source == "" {
		source = defaultOpenMeterSource
	}
	return newOpenMeterClient(n.OpenMeterIngestURL.String(), n.OpenMeterAPIToken, source)
}

func reportLLMUsageAsync(ctx context.Context, node *core.LivepeerNode, headers map[string]string, report LLMUsageReport) {
	if node == nil || node.RemoteSignerUrl == nil {
		return
	}
	if err := report.Validate(); err != nil {
		clog.Warningf(ctx, "Skipping invalid LLM usage report err=%q", err)
		monitor.LLMUsageIngestError("invalid_report")
		return
	}
	copied := make(map[string]string, len(headers))
	for k, v := range headers {
		if strings.EqualFold(k, llmProviderAPIKeyHeader) {
			continue
		}
		copied[k] = v
	}
	go func() {
		if err := postLLMUsageReport(context.Background(), node.RemoteSignerUrl, copied, report); err != nil {
			clog.Errorf(ctx, "LLM usage report failed err=%q", err)
			monitor.LLMUsageIngestError("report_failed")
		}
	}()
}

func postLLMUsageReport(ctx context.Context, signerURL *url.URL, headers map[string]string, report LLMUsageReport) error {
	if signerURL == nil {
		return errors.New("remote signer not configured")
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	endpoint := signerURL.ResolveReference(&url.URL{Path: llmUsageReportPath})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := llmUsageReportClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("remote signer returned status %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

func reportWorkerLLMUsage(ctx context.Context, params aiRequestParams, req worker.GenLLMJSONRequestBody, usage worker.LLMTokenUsage, gotUsage bool) {
	if !gotUsage {
		monitor.LLMUsageIngestError("missing_usage")
		return
	}
	model := ""
	if req.Model != nil {
		model = *req.Model
	}
	if model == "" {
		monitor.LLMUsageIngestError("missing_model")
		return
	}
	requestID := clog.GetVal(ctx, "request_id")
	if requestID == "" {
		requestID = string(core.RandomManifestID())
	}
	reportLLMUsageAsync(ctx, params.node, params.llmSignerHeaders, LLMUsageReport{
		RequestID:      requestID,
		Provider:       "livepeer",
		Model:          model,
		InputTokens:    usage.PromptTokens,
		OutputTokens:   usage.CompletionTokens,
		CredentialMode: credentialModeFromHeaders(params.llmSignerHeaders),
		Route:          LLMUsageRouteLLM,
	})
}
