package byoc

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/golang/glog"
	"github.com/google/uuid"
)

// PendingEvent is a durable lifecycle event stored on the orchestrator.
// Multiple gateways can drain the same events; the UUID assigned at insert
// time lets Kafka consumers deduplicate across gateways.
type PendingEvent struct {
	ID        int64           `json:"id"`
	UUID      string          `json:"uuid"`
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	CreatedAt int64           `json:"created_at_ms"`
}

// PendingEventStore persists orchestrator lifecycle events in the
// orch_pending_events SQLite table. Events are never deleted on read; they
// survive orchestrator restarts and are purged by the daily purge goroutine.
type PendingEventStore struct {
	db *sql.DB
}

// NewPendingEventStore creates a store backed by the given DB connection.
func NewPendingEventStore(db *sql.DB) *PendingEventStore {
	return &PendingEventStore{db: db}
}

// Enqueue inserts a new lifecycle event. A UUID is assigned here so that the
// same event always carries the same UUID regardless of which gateway reads it.
func (s *PendingEventStore) Enqueue(eventType string, data interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	id := uuid.New().String()
	now := time.Now().UnixMilli()
	_, err = s.db.Exec(
		`INSERT INTO orch_pending_events (event_uuid, type, data, created_at) VALUES (?, ?, ?, ?)`,
		id, eventType, string(b), now,
	)
	return err
}

// Since returns all events with created_at > sinceMs ordered by id ASC.
// Events are not deleted; the gateway advances its own cursor.
func (s *PendingEventStore) Since(sinceMs int64) ([]PendingEvent, error) {
	rows, err := s.db.Query(
		`SELECT id, event_uuid, type, data, created_at FROM orch_pending_events WHERE created_at > ? ORDER BY id ASC`,
		sinceMs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []PendingEvent
	for rows.Next() {
		var e PendingEvent
		var dataStr string
		if err := rows.Scan(&e.ID, &e.UUID, &e.Type, &dataStr, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Data = json.RawMessage(dataStr)
		events = append(events, e)
	}
	return events, rows.Err()
}

// Purge removes events older than maxAge. Returns the number of rows deleted.
func (s *PendingEventStore) Purge(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UnixMilli()
	res, err := s.db.Exec(`DELETE FROM orch_pending_events WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// StartDailyPurge launches a background goroutine that purges events older
// than maxAge once every 24 hours.
func (s *PendingEventStore) StartDailyPurge(maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		for range ticker.C {
			n, err := s.Purge(maxAge)
			glog.Infof("byoc: purged %d stale orch_pending_events err=%v", n, err)
		}
	}()
}
