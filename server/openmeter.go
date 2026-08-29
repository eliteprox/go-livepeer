package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const openMeterMaxAttempts = 3

type openMeterClient struct {
	ingestURL  string
	apiToken   string
	source     string
	httpClient *http.Client
	now        func() time.Time
	sleep      func(time.Duration)
}

func newOpenMeterClient(ingestURL, apiToken, source string) *openMeterClient {
	return &openMeterClient{
		ingestURL: ingestURL,
		apiToken:  apiToken,
		source:    source,
		httpClient: &http.Client{
			Timeout: llmUsageReportTimeout,
		},
		now:   time.Now,
		sleep: time.Sleep,
	}
}

func (c *openMeterClient) Ingest(ctx context.Context, subject string, report LLMUsageReport) error {
	events := llmUsageCloudEvents(subject, c.source, report, c.now().UTC())
	for _, event := range events {
		if err := c.postEvent(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func (c *openMeterClient) postEvent(ctx context.Context, event llmUsageCloudEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 1; attempt <= openMeterMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = c.doPost(ctx, body)
		if lastErr == nil {
			return nil
		}
		if !retryableOpenMeterError(lastErr) {
			return lastErr
		}
		if attempt < openMeterMaxAttempts {
			c.sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
	}
	return lastErr
}

func (c *openMeterClient) doPost(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ingestURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return &openMeterStatusError{status: resp.StatusCode}
}

type openMeterStatusError struct {
	status int
}

func (e *openMeterStatusError) Error() string {
	return fmt.Sprintf("openmeter status %d", e.status)
}

func retryableOpenMeterError(err error) bool {
	var statusErr *openMeterStatusError
	if errors.As(err, &statusErr) {
		return statusErr.status >= 500 || statusErr.status == http.StatusTooManyRequests
	}
	return true
}
