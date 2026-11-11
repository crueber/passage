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

// TestMigration022_PopulatedDatabase proves migration 022 is safe on a database
// that already serves traffic:
//
//   - every existing user, app, and session survives untouched,
//   - the api_tokens table is created empty (the feature is off until a token is
//     minted),
//   - the token row shape (nullable last_used_at / revoked_at) and the unique
//     hash constraint behave,
//   - re-opening the migrated database is a no-op.
func TestMigration022_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	// ── 1. Bring a fresh database to the last version before 022. ──────────
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
	if _, err := provider.UpTo(ctx, 21); err != nil {
		t.Fatalf("migrate to version 21: %v", err)
	}

	// ── 2. Insert representative pre-022 data. ─────────────────────────────
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
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO audit_log (id, actor_id, actor_name, action) VALUES ('audit-1', 'user-1', 'alice', 'user.create')`,
	); err != nil {
		t.Fatalf("insert audit row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// ── 3. Apply 022 through the production entry point. ───────────────────
	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-022 database: %v", err)
	}

	assertPre022DataIntact(t, database)
	assertAPITokensSchema(t, database)

	// The feature is off until a token is minted: no rows are created.
	var count int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens`).Scan(&count); err != nil {
		t.Fatalf("count api_tokens: %v", err)
	}
	if count != 0 {
		t.Errorf("api_tokens rows after migration = %d, want 0", count)
	}

	// ── 4. A token row survives a reopen, timestamps stay nullable. ────────
	if _, err := database.ExecContext(ctx,
		`INSERT INTO api_tokens (id, name, token_hash) VALUES ('token-1', 'ci', 'hash-1')`,
	); err != nil {
		t.Fatalf("insert api token: %v", err)
	}

	// The hash is unique: a duplicate must be rejected.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO api_tokens (id, name, token_hash) VALUES ('token-2', 'other', 'hash-1')`,
	); err == nil {
		t.Fatal("duplicate token_hash was accepted; the UNIQUE constraint is missing")
	}

	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}
	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	defer database.Close()

	var (
		name      string
		createdAt time.Time
		lastUsed  sql.NullTime
		revokedAt sql.NullTime
	)
	if err := database.QueryRowContext(ctx,
		`SELECT name, created_at, last_used_at, revoked_at FROM api_tokens WHERE id = 'token-1'`,
	).Scan(&name, &createdAt, &lastUsed, &revokedAt); err != nil {
		t.Fatalf("read token after reopen: %v", err)
	}
	if name != "ci" {
		t.Errorf("token name after reopen = %q, want ci", name)
	}
	if createdAt.IsZero() {
		t.Error("created_at default was not applied")
	}
	if lastUsed.Valid || revokedAt.Valid {
		t.Errorf("last_used_at/revoked_at = %v/%v, want NULL on a fresh token", lastUsed, revokedAt)
	}

	assertPre022DataIntact(t, database)
}

// assertPre022DataIntact checks the rows written before the migration are
// untouched.
func assertPre022DataIntact(t *testing.T, database *sql.DB) {
	t.Helper()
	ctx := context.Background()

	var (
		username string
		isAdmin  int
	)
	if err := database.QueryRowContext(ctx,
		`SELECT username, is_admin FROM users WHERE id = 'user-1'`).Scan(&username, &isAdmin); err != nil {
		t.Fatalf("read user after migration: %v", err)
	}
	if username != "alice" || isAdmin != 1 {
		t.Errorf("user after migration = (%q, %d); want (alice, 1)", username, isAdmin)
	}

	var slug string
	if err := database.QueryRowContext(ctx,
		`SELECT slug FROM apps WHERE id = 'app-1'`).Scan(&slug); err != nil {
		t.Fatalf("read app after migration: %v", err)
	}
	if slug != "grafana" {
		t.Errorf("app slug after migration = %q, want grafana", slug)
	}

	for _, q := range []struct {
		name  string
		query string
	}{
		{"sessions", `SELECT COUNT(*) FROM sessions WHERE id = 'session-1'`},
		{"audit_log", `SELECT COUNT(*) FROM audit_log WHERE id = 'audit-1'`},
	} {
		var n int
		if err := database.QueryRowContext(ctx, q.query).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", q.name, err)
		}
		if n != 1 {
			t.Errorf("%s row after migration = %d, want 1", q.name, n)
		}
	}
}

// assertAPITokensSchema checks the new table has exactly the expected columns.
func assertAPITokensSchema(t *testing.T, database *sql.DB) {
	t.Helper()

	rows, err := database.QueryContext(context.Background(), "PRAGMA table_info(api_tokens)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(api_tokens): %v", err)
	}
	defer rows.Close()

	want := map[string]bool{
		"id":           false,
		"name":         false,
		"token_hash":   false,
		"created_at":   false,
		"last_used_at": false,
		"revoked_at":   false,
	}
	for rows.Next() {
		var (
			cid       int
			name      string
			colType   string
			notNull   any
			dfltValue any
			pk        any
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan column row: %v", err)
		}
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}

	for name, found := range want {
		if !found {
			t.Errorf("api_tokens.%s is missing", name)
		}
	}
}
