package db_test

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/crueber/passage/internal/db"
)

// TestMigration033_MagicLinkThrottleIsSafeOnPopulatedDB proves the additive
// magic-link throttle migration can be applied to an existing database and
// re-run on the next start without disturbing the rows around it.
func TestMigration033_MagicLinkThrottleIsSafeOnPopulatedDB(t *testing.T) {
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
		INSERT INTO magic_link_throttle (ip, failures, window_started, locked_until)
		VALUES ('198.51.100.10', 3, '2026-11-10 12:00:00.000000000', '2026-11-11 12:00:00.000000000')`); err != nil {
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

	var username, email string
	if err := second.QueryRowContext(ctx,
		`SELECT username, email FROM users WHERE id = 'user-1'`,
	).Scan(&username, &email); err != nil {
		t.Fatalf("user row not intact: %v", err)
	}
	if username != "alice" || email != "alice@example.com" {
		t.Errorf("user row changed: %q, %q", username, email)
	}

	var (
		failures    int
		windowStart time.Time
		lockedUntil time.Time
	)
	if err := second.QueryRowContext(ctx,
		`SELECT failures, window_started, locked_until FROM magic_link_throttle WHERE ip = '198.51.100.10'`,
	).Scan(&failures, &windowStart, &lockedUntil); err != nil {
		t.Fatalf("throttle row not intact: %v", err)
	}
	if failures != 3 {
		t.Errorf("failures = %d, want 3", failures)
	}
	if want := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC); !windowStart.Equal(want) {
		t.Errorf("window_started = %v, want %v", windowStart, want)
	}
	if want := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC); !lockedUntil.Equal(want) {
		t.Errorf("locked_until = %v, want %v", lockedUntil, want)
	}

	// The index named in the migration exists.
	var found string
	if err := second.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`,
		"idx_magic_link_throttle_locked",
	).Scan(&found); err != nil {
		t.Errorf("index idx_magic_link_throttle_locked not found: %v", err)
	}

	// Deliberately no foreign key: the key is a client address, not a user.
	rows, err := second.QueryContext(ctx, `PRAGMA foreign_key_list(magic_link_throttle)`)
	if err != nil {
		t.Fatalf("PRAGMA foreign_key_list: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Error("magic_link_throttle has a foreign key; it must be standalone")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_list rows: %v", err)
	}
}
