package testutil

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	"github.com/crueber/passage/internal/db"
)

// NewTestDB opens an in-memory SQLite database, runs all migrations,
// and registers a cleanup function to close it.
func NewTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := db.Open(context.Background(), ":memory:", slog.Default())
	if err != nil {
		t.Fatalf("testutil.NewTestDB: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}
