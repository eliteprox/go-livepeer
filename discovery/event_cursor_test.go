package discovery

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openCursorTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file::memory:?cache=shared&_foreign_keys=1")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS gateway_event_cursors (
			orch_url   TEXT    PRIMARY KEY,
			cursor_ms  INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestEventCursorStore_GetReturnsZeroWhenNotSet(t *testing.T) {
	store := NewEventCursorStore(openCursorTestDB(t))

	cursor, err := store.Get("http://orch1:8935")
	require.NoError(t, err)
	assert.EqualValues(t, 0, cursor)
}

func TestEventCursorStore_SetAndGet(t *testing.T) {
	store := NewEventCursorStore(openCursorTestDB(t))

	require.NoError(t, store.Set("http://orch1:8935", 12345))

	cursor, err := store.Get("http://orch1:8935")
	require.NoError(t, err)
	assert.EqualValues(t, 12345, cursor)
}

func TestEventCursorStore_SetUpserts(t *testing.T) {
	store := NewEventCursorStore(openCursorTestDB(t))

	require.NoError(t, store.Set("http://orch1:8935", 1000))
	require.NoError(t, store.Set("http://orch1:8935", 9999))

	cursor, err := store.Get("http://orch1:8935")
	require.NoError(t, err)
	assert.EqualValues(t, 9999, cursor)
}

func TestEventCursorStore_MultipleOrchsIndependent(t *testing.T) {
	store := NewEventCursorStore(openCursorTestDB(t))

	require.NoError(t, store.Set("http://orch1:8935", 100))
	require.NoError(t, store.Set("http://orch2:8935", 200))

	c1, err := store.Get("http://orch1:8935")
	require.NoError(t, err)
	assert.EqualValues(t, 100, c1)

	c2, err := store.Get("http://orch2:8935")
	require.NoError(t, err)
	assert.EqualValues(t, 200, c2)
}
