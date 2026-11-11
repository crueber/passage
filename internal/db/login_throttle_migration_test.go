package db_test

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/crueber/passage/internal/db"
)

// TestMigration017_LoginThrottleIsSafeOnPopulatedDB proves the additive
// migration can be applied to an existing database and re-run (on the next
// start) without disturbing the rows around it.
func TestMigration017_LoginThrottleIsSafeOnPopulatedDB(t *testing.T) {
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
		INSERT INTO login_throttle (username, failures, locked_until)
		VALUES ('alice', 0, '2026-11-10 12:15:00.000000000')`); err != nil {
		t.Fatalf("insert throttle row: %v", err)
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

	var failures int
	var lockedUntil time.Time
	if err := second.QueryRowContext(ctx,
		`SELECT failures, locked_until FROM login_throttle WHERE username = 'alice'`,
	).Scan(&failures, &lockedUntil); err != nil {
		t.Fatalf("throttle row not intact: %v", err)
	}
	wantUntil := time.Date(2026, 11, 10, 12, 15, 0, 0, time.UTC)
	if failures != 0 || !lockedUntil.Equal(wantUntil) {
		t.Errorf("throttle row changed: failures=%d locked_until=%v", failures, lockedUntil)
	}

	// The index named in the migration exists.
	var found string
	if err := second.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`,
		"login_throttle_locked_until",
	).Scan(&found); err != nil {
		t.Errorf("index login_throttle_locked_until not found: %v", err)
	}

	// Deliberately no foreign key to users: unknown usernames have no user row,
	// and deleting a user must not leave an unclearable lock behind.
	rows, err := second.QueryContext(ctx, `PRAGMA foreign_key_list(login_throttle)`)
	if err != nil {
		t.Fatalf("PRAGMA foreign_key_list: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Error("login_throttle has a foreign key; it must be standalone")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_list rows: %v", err)
	}
}
