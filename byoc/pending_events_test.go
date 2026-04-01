package byoc

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openTestDB opens an in-memory SQLite database and creates the
// orch_pending_events table used by PendingEventStore.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file::memory:?cache=shared&_foreign_keys=1")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS orch_pending_events (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			event_uuid TEXT    NOT NULL,
			type       TEXT    NOT NULL,
			data       TEXT    NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_orch_pending_events_created_at
			ON orch_pending_events(created_at);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPendingEventStore_EnqueueAndSince(t *testing.T) {
	db := openTestDB(t)
	store := NewPendingEventStore(db)

	before := time.Now().UnixMilli()

	require.NoError(t, store.Enqueue("worker_registered", map[string]interface{}{
		"capability": "text-to-image",
		"worker_url": "http://worker1:8000",
	}))
	require.NoError(t, store.Enqueue("worker_unregistered", map[string]interface{}{
		"capability": "text-to-image",
		"reason":     "explicit_deregister",
	}))

	// Since(0) returns all events
	events, err := store.Since(0)
	require.NoError(t, err)
	require.Len(t, events, 2)

	assert.NotEmpty(t, events[0].UUID)
	assert.NotEmpty(t, events[1].UUID)
	assert.NotEqual(t, events[0].UUID, events[1].UUID, "UUIDs must be unique per event")
	assert.Equal(t, "worker_registered", events[0].Type)
	assert.Equal(t, "worker_unregistered", events[1].Type)
	assert.True(t, events[0].CreatedAt >= before)
	assert.True(t, events[0].ID < events[1].ID, "events ordered by id ASC")

	// Since(cursor) only returns events after cursor
	events2, err := store.Since(events[0].CreatedAt)
	require.NoError(t, err)
	// may return 0 or 1 depending on timestamp granularity; must not include first event
	for _, e := range events2 {
		assert.True(t, e.CreatedAt > events[0].CreatedAt)
	}

	// Data is valid JSON
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(events[0].Data, &payload))
	assert.Equal(t, "text-to-image", payload["capability"])
}

func TestPendingEventStore_Since_EmptyResult(t *testing.T) {
	db := openTestDB(t)
	store := NewPendingEventStore(db)

	events, err := store.Since(0)
	require.NoError(t, err)
	assert.Len(t, events, 0)
}

func TestPendingEventStore_Purge(t *testing.T) {
	db := openTestDB(t)
	store := NewPendingEventStore(db)

	require.NoError(t, store.Enqueue("worker_registered", map[string]interface{}{"cap": "a"}))
	require.NoError(t, store.Enqueue("worker_registered", map[string]interface{}{"cap": "b"}))

	events, err := store.Since(0)
	require.NoError(t, err)
	require.Len(t, events, 2)

	// Purge with negative maxAge sets cutoff to a future time, removing all events
	n, err := store.Purge(-1 * time.Second)
	require.NoError(t, err)
	assert.EqualValues(t, int64(2), n)

	events, err = store.Since(0)
	require.NoError(t, err)
	assert.Len(t, events, 0)
}

func TestPendingEventStore_Purge_KeepsRecent(t *testing.T) {
	db := openTestDB(t)
	store := NewPendingEventStore(db)

	require.NoError(t, store.Enqueue("worker_registered", map[string]interface{}{"cap": "a"}))

	// Purge events older than 1 hour — the just-inserted event is recent, should survive
	n, err := store.Purge(1 * time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)

	events, err := store.Since(0)
	require.NoError(t, err)
	assert.Len(t, events, 1)
}

func TestPendingEventStore_Since_ReturnsOnlyAfterCursor(t *testing.T) {
	db := openTestDB(t)
	store := NewPendingEventStore(db)

	// Insert with a known created_at by manipulating via raw SQL
	_, err := db.Exec(
		`INSERT INTO orch_pending_events (event_uuid, type, data, created_at) VALUES (?, ?, ?, ?)`,
		"uuid-old", "worker_registered", `{"cap":"old"}`, int64(1000),
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO orch_pending_events (event_uuid, type, data, created_at) VALUES (?, ?, ?, ?)`,
		"uuid-new", "worker_unregistered", `{"cap":"new"}`, int64(2000),
	)
	require.NoError(t, err)

	// Since(1000) should only return the event at created_at=2000
	events, err := store.Since(1000)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "uuid-new", events[0].UUID)
	assert.EqualValues(t, 2000, events[0].CreatedAt)
}
