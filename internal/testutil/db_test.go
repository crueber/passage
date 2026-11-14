package testutil_test

import (
	"testing"

	"github.com/crueber/passage/internal/testutil"
)

func TestNewTestDB(t *testing.T) {
	database := testutil.NewTestDB(t)

	if database == nil {
		t.Fatal("NewTestDB returned nil")
	}

	// Verify the schema was applied by checking a known table exists.
	var name string
	err := database.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='users'",
	).Scan(&name)
	if err != nil {
		t.Fatalf("users table not found after NewTestDB: %v", err)
	}

	if name != "users" {
		t.Errorf("got table name %q; want %q", name, "users")
	}
}
