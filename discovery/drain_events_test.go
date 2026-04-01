package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/livepeer/go-livepeer/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLifecycleEventTopic(t *testing.T) {
	tests := []struct {
		eventType string
		want      string
	}{
		{"worker_registered", "worker_lifecycle"},
		{"worker_unregistered", "worker_lifecycle"},
		{"worker_capacity_exhausted", "worker_lifecycle"},
		{"job_orchestrator_received", ""},
		{"unknown", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			assert.Equal(t, tt.want, lifecycleEventTopic(tt.eventType))
		})
	}
}

func TestFetchOrchEventsSince_Success(t *testing.T) {
	events := []orchPendingEvent{
		{ID: 1, UUID: "uuid-1", Type: "worker_registered", Data: json.RawMessage(`{"cap":"img"}`), CreatedAt: 1000},
		{ID: 2, UUID: "uuid-2", Type: "worker_unregistered", Data: json.RawMessage(`{"cap":"img"}`), CreatedAt: 2000},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/events/drain", r.URL.Path)
		assert.Equal(t, "500", r.URL.Query().Get("since_ms"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}))
	defer ts.Close()

	ctx := context.Background()
	got, err := fetchOrchEventsSince(ctx, ts.URL, 500)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "uuid-1", got[0].UUID)
	assert.Equal(t, "worker_registered", got[0].Type)
	assert.EqualValues(t, 1000, got[0].CreatedAt)
}

func TestFetchOrchEventsSince_EmptyList(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]orchPendingEvent{})
	}))
	defer ts.Close()

	got, err := fetchOrchEventsSince(context.Background(), ts.URL, 0)
	require.NoError(t, err)
	assert.Len(t, got, 0)
}

func TestFetchOrchEventsSince_404ReturnsNotSupported(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	_, err := fetchOrchEventsSince(context.Background(), ts.URL, 0)
	assert.ErrorIs(t, err, errOrchEventsDrainNotSupported)
}

func TestFetchOrchEventsSince_500ReturnsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, err := fetchOrchEventsSince(context.Background(), ts.URL, 0)
	require.Error(t, err)
	assert.NotErrorIs(t, err, errOrchEventsDrainNotSupported)
}

func TestFetchOrchEventsSince_ConnectionError(t *testing.T) {
	// Use a non-existent server
	_, err := fetchOrchEventsSince(context.Background(), "http://127.0.0.1:19999", 0)
	require.Error(t, err)
}

func TestDrainOrchEvents_NotSupportedSilent(t *testing.T) {
	// Orchestrator returns 404 (old version) — drainOrchEvents should return silently
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	db := openCursorTestDB(t)
	store := NewEventCursorStore(db)
	dbo := &DBOrchestratorPoolCache{cursorStore: store}

	cap := &common.OrchNetworkCapabilities{Address: "0xabc", OrchURI: ts.URL}
	// Should complete without panic or log at warning level
	dbo.drainOrchEvents(cap)
}

func TestDrainOrchEvents_AdvancesCursor(t *testing.T) {
	events := []orchPendingEvent{
		{ID: 1, UUID: "uuid-1", Type: "worker_registered", Data: json.RawMessage(`{"cap":"img"}`), CreatedAt: 5000},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}))
	defer ts.Close()

	db := openCursorTestDB(t)
	store := NewEventCursorStore(db)
	dbo := &DBOrchestratorPoolCache{cursorStore: store}

	cap := &common.OrchNetworkCapabilities{Address: "0xabc", OrchURI: ts.URL}
	dbo.drainOrchEvents(cap)

	// Cursor should have advanced to the created_at of the last event
	cursor, err := store.Get(ts.URL)
	require.NoError(t, err)
	assert.EqualValues(t, 5000, cursor)
}
