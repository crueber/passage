package db_test

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/crueber/passage/internal/db"
)

// TestMigration014_AuthEventsIsSafeOnPopulatedDB proves the additive migration
// can be applied to an existing database and re-run (on the next start) without
// disturbing the rows around it.
func TestMigration014_AuthEventsIsSafeOnPopulatedDB(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "populated.db")

	first, err := db.Open(ctx, path, slog.Default())
	if err != nil {
		t.Fatalf("first db.Open: %v", err)
	}

	if _, err := first.ExecContext(ctx, `
		INSERT INTO users (id, username, email, password_hash, is_admin, is_active, roles)
		VALUES ('user-1', 'alice', 'alice@example.com', 'hash', 0, 1, '[]')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := first.ExecContext(ctx, `
		INSERT INTO apps (id, slug, name, host_pattern)
		VALUES ('app-1', 'myapp', 'My App', 'myapp.example.com')`); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	if _, err := first.ExecContext(ctx, `
		INSERT INTO auth_events (id, event, outcome, user_id, username, ip_address, user_agent, detail)
		VALUES ('event-1', 'login.failure', 'failure', '', 'ghost', '192.0.2.1', 'test-agent', 'invalid credentials')`); err != nil {
		t.Fatalf("insert auth event: %v", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first db: %v", err)
	}

	// Re-open: goose re-runs its bookkeeping and the migration must be a no-op.
	second, err := db.Open(ctx, path, slog.Default())
	if err != nil {
		t.Fatalf("second db.Open: %v", err)
	}
	defer second.Close()

	var username, email, hash string
	if err := second.QueryRowContext(ctx,
		`SELECT username, email, password_hash FROM users WHERE id = 'user-1'`,
	).Scan(&username, &email, &hash); err != nil {
		t.Fatalf("user row not intact: %v", err)
	}
	if username != "alice" || email != "alice@example.com" || hash != "hash" {
		t.Errorf("user row changed: %q, %q, %q", username, email, hash)
	}

	var slug, name, hostPattern string
	if err := second.QueryRowContext(ctx,
		`SELECT slug, name, host_pattern FROM apps WHERE id = 'app-1'`,
	).Scan(&slug, &name, &hostPattern); err != nil {
		t.Fatalf("app row not intact: %v", err)
	}
	if slug != "myapp" || name != "My App" || hostPattern != "myapp.example.com" {
		t.Errorf("app row changed: %q, %q, %q", slug, name, hostPattern)
	}

	var event, outcome, eventUsername, detail string
	if err := second.QueryRowContext(ctx,
		`SELECT event, outcome, username, detail FROM auth_events WHERE id = 'event-1'`,
	).Scan(&event, &outcome, &eventUsername, &detail); err != nil {
		t.Fatalf("auth event row not intact: %v", err)
	}
	if event != "login.failure" || outcome != "failure" || eventUsername != "ghost" || detail != "invalid credentials" {
		t.Errorf("auth event row changed: %q, %q, %q, %q", event, outcome, eventUsername, detail)
	}

	// The indexes named in the migration exist.
	for _, index := range []string{"auth_events_created_at", "auth_events_event", "auth_events_user_id"} {
		var found string
		if err := second.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, index,
		).Scan(&found); err != nil {
			t.Errorf("index %q not found: %v", index, err)
		}
	}

	// Deliberately no foreign key to users: a failed login for an unknown
	// username has no user row, and deleting a user must not erase history.
	rows, err := second.QueryContext(ctx, `PRAGMA foreign_key_list(auth_events)`)
	if err != nil {
		t.Fatalf("PRAGMA foreign_key_list: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Error("auth_events has a foreign key; it must be a standalone append-only log")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_list rows: %v", err)
	}
}
