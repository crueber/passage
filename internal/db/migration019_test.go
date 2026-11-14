package db

import (
	"context"
	"database/sql"
	"io/fs"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

// TestMigration019_PopulatedDatabase proves migration 019 is safe on a database
// that is already serving traffic:
//
//   - every existing row survives with its data intact,
//   - the three MFA tables and their index exist afterwards,
//   - a user deleting cascades through all three,
//   - re-opening the migrated database is a no-op.
//
// It builds the pre-019 schema with goose, inserts representative rows, and then
// hands the file to db.Open — the same path a deploying process takes.
func TestMigration019_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	// ── 1. Bring a fresh database to the last version before 019. ──────────
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	raw.SetMaxOpenConns(1)
	if _, err := raw.ExecContext(ctx, "PRAGMA foreign_keys=ON;"); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}

	migrationsFS, err := fs.Sub(migrations, "migrations")
	if err != nil {
		t.Fatalf("create migrations sub-fs: %v", err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, raw, migrationsFS, goose.WithSlog(logger))
	if err != nil {
		t.Fatalf("create migration provider: %v", err)
	}
	if _, err := provider.UpTo(ctx, 18); err != nil {
		t.Fatalf("migrate to version 18: %v", err)
	}

	// ── 2. Insert representative pre-019 data. ─────────────────────────────
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users (id, username, email, is_admin) VALUES ('user-1', 'alice', 'alice@example.com', 1)`,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO apps (id, slug, name, host_pattern) VALUES ('app-1', 'grafana', 'Grafana', 'grafana.example.com')`,
	); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		 VALUES ('session-1', 'public-1', 'user-1', 'app-1', '192.0.2.1', 'Agent/1', ?, ?)`,
		created.Add(24*time.Hour), created,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// ── 3. Apply 019 through the production entry point. ───────────────────
	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-019 database: %v", err)
	}

	// Existing data is untouched.
	var username string
	var isAdmin int
	if err := database.QueryRowContext(ctx,
		`SELECT username, is_admin FROM users WHERE id = 'user-1'`).Scan(&username, &isAdmin); err != nil {
		t.Fatalf("read user after migration: %v", err)
	}
	if username != "alice" || isAdmin != 1 {
		t.Errorf("user after migration = (%q, %d); want (alice, 1)", username, isAdmin)
	}
	var sessions int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 1 {
		t.Errorf("sessions after migration = %d; want 1", sessions)
	}

	// The new tables and index exist.
	for _, name := range []string{"user_mfa", "user_mfa_recovery_codes", "mfa_challenges", "mfa_challenges_user_id"} {
		var found int
		if err := database.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, name).Scan(&found); err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		if found != 1 {
			t.Errorf("schema object %q not found after migration", name)
		}
	}

	// ── 4. MFA rows persist across a reopen. ───────────────────────────────
	if _, err := database.ExecContext(ctx,
		`INSERT INTO user_mfa (user_id, secret) VALUES ('user-1', 'JBSWY3DPEHPK3PXP')`); err != nil {
		t.Fatalf("insert user_mfa: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO user_mfa_recovery_codes (user_id, hash) VALUES ('user-1', 'deadbeef')`); err != nil {
		t.Fatalf("insert recovery code: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO mfa_challenges (token, user_id, return_to, expires_at) VALUES ('challenge-1', 'user-1', '/', ?)`,
		time.Now().UTC().Add(5*time.Minute)); err != nil {
		t.Fatalf("insert challenge: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}

	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	defer database.Close()

	var mfaRows int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_mfa`).Scan(&mfaRows); err != nil {
		t.Fatalf("count user_mfa: %v", err)
	}
	if mfaRows != 1 {
		t.Errorf("user_mfa rows after reopen = %d; want 1", mfaRows)
	}

	// ── 5. Deleting a user cascades through all three tables. ──────────────
	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 'user-1'`); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	for _, table := range []string{"user_mfa", "user_mfa_recovery_codes", "mfa_challenges"} {
		var n int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s kept %d rows after the user was deleted", table, n)
		}
	}
}
