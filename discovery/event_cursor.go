package discovery

import (
	"database/sql"
	"time"
)

// EventCursorStore persists the per-orchestrator drain cursor for the gateway.
// Each cursor tracks the last created_at_ms seen from that orchestrator's
// /events/drain endpoint, so a gateway restart re-fetches from the last
// known position rather than from the beginning of time.
type EventCursorStore struct {
	db *sql.DB
}

// NewEventCursorStore creates a store backed by the given DB connection.
func NewEventCursorStore(db *sql.DB) *EventCursorStore {
	return &EventCursorStore{db: db}
}

// Get returns the stored cursor (unix ms) for orchURL, or 0 if not yet set.
func (s *EventCursorStore) Get(orchURL string) (int64, error) {
	var cursor int64
	err := s.db.QueryRow(
		`SELECT cursor_ms FROM gateway_event_cursors WHERE orch_url = ?`, orchURL,
	).Scan(&cursor)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return cursor, err
}

// Set upserts the cursor for orchURL.
func (s *EventCursorStore) Set(orchURL string, cursorMs int64) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(
		`INSERT INTO gateway_event_cursors (orch_url, cursor_ms, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(orch_url) DO UPDATE SET cursor_ms = excluded.cursor_ms, updated_at = excluded.updated_at`,
		orchURL, cursorMs, now,
	)
	return err
}
