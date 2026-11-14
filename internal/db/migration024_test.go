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

// TestMigration024_PopulatedDatabase proves migration 024 (scope registry,
// resource indicators, JWT revocation denylist) is safe on a database that is
// already serving traffic:
//
//   - every existing user, app, session, code, token, and refresh token
//     survives untouched,
//   - the new app columns default to the empty string, which means "no
//     registry" and therefore exactly the previous behaviour,
//   - an existing authorization code gets an empty resource, so the token
//     endpoint keeps issuing a client-id audience for it,
//   - the denylist table is created and works,
//   - reopening an already-migrated database changes nothing.
func TestMigration024_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	// ── 1. Bring a fresh database to the last version before 024. ──────────
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
	if _, err := provider.UpTo(ctx, 23); err != nil {
		t.Fatalf("migrate to version 23: %v", err)
	}

	// ── 2. Insert representative pre-024 data. ─────────────────────────────
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	expires := created.Add(24 * time.Hour)
	for _, stmt := range []struct {
		name string
		sql  string
		args []any
	}{
		{
			name: "user",
			sql:  `INSERT INTO users (id, username, email, is_admin) VALUES ('user-1', 'alice', 'alice@example.com', 1)`,
		},
		{
			name: "app",
			sql: `INSERT INTO apps (id, slug, name, host_pattern, is_active, client_id, redirect_uris, oauth_enabled)
			      VALUES ('app-1', 'grafana', 'Grafana', 'grafana.example.com', 1, 'client-1', 'https://rp.example.com/cb', 1)`,
		},
		{
			name: "session",
			sql: `INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
			      VALUES ('session-1', 'public-1', 'user-1', 'app-1', '192.0.2.1', 'Agent/1', ?, ?)`,
			args: []any{expires, created},
		},
		{
			name: "authorization code",
			sql: `INSERT INTO oauth_codes (code, app_id, user_id, redirect_uri, scopes, expires_at, created_at)
			      VALUES ('code-1', 'app-1', 'user-1', 'https://rp.example.com/cb', 'openid profile', ?, ?)`,
			args: []any{expires, created},
		},
		{
			name: "opaque access token",
			sql: `INSERT INTO oauth_tokens (token, app_id, user_id, scopes, expires_at, created_at)
			      VALUES ('token-1', 'app-1', 'user-1', 'openid', ?, ?)`,
			args: []any{expires, created},
		},
		{
			name: "refresh token",
			sql: `INSERT INTO oauth_refresh_tokens (token, app_id, user_id, scopes, family_id, expires_at, created_at)
			      VALUES ('refresh-1', 'app-1', 'user-1', 'openid', 'family-1', ?, ?)`,
			args: []any{expires, created},
		},
	} {
		if _, err := raw.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("insert %s: %v", stmt.name, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// ── 3. Apply 024 through the production entry point. ───────────────────
	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-024 database: %v", err)
	}
	defer database.Close()

	assertPre024DataIntact(t, database)
	assertNewColumnsDefaultEmpty(t, database)
	assertDenylistTable(t, database)

	// ── 4. Reopening an already-migrated database changes nothing. ─────────
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}
	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	assertPre024DataIntact(t, database)
	assertNewColumnsDefaultEmpty(t, database)
}

// assertPre024DataIntact checks the rows written before the migration are
// untouched.
func assertPre024DataIntact(t *testing.T, database *sql.DB) {
	t.Helper()
	ctx := context.Background()

	checks := []struct {
		name  string
		query string
		want  string
	}{
		{"user", `SELECT username FROM users WHERE id = 'user-1'`, "alice"},
		{"app", `SELECT slug FROM apps WHERE id = 'app-1'`, "grafana"},
		{"app client", `SELECT client_id FROM apps WHERE id = 'app-1'`, "client-1"},
		{"session", `SELECT COUNT(*) FROM sessions WHERE id = 'session-1'`, "1"},
		{"access token", `SELECT COUNT(*) FROM oauth_tokens WHERE token = 'token-1'`, "1"},
		{"refresh token", `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE token = 'refresh-1'`, "1"},
	}
	for _, c := range checks {
		var got string
		if err := database.QueryRowContext(ctx, c.query).Scan(&got); err != nil {
			t.Fatalf("read %s after migration: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s after migration = %q, want %q", c.name, got, c.want)
		}
	}
}

// assertNewColumnsDefaultEmpty checks an app and an authorization code that
// predate the migration read back as "no registry" and "no resource".
func assertNewColumnsDefaultEmpty(t *testing.T, database *sql.DB) {
	t.Helper()
	ctx := context.Background()

	var scopes, resources, codeScopes, codeResource string
	if err := database.QueryRowContext(ctx,
		`SELECT scopes, resources FROM apps WHERE id = 'app-1'`).Scan(&scopes, &resources); err != nil {
		t.Fatalf("read app registries: %v", err)
	}
	if scopes != "" || resources != "" {
		t.Errorf("pre-024 app registries = (%q, %q), want empty", scopes, resources)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT scopes, resource FROM oauth_codes WHERE code = 'code-1'`).Scan(&codeScopes, &codeResource); err != nil {
		t.Fatalf("read code resource: %v", err)
	}
	if codeScopes != "openid profile" {
		t.Errorf("existing code scope = %q, want openid profile", codeScopes)
	}
	if codeResource != "" {
		t.Errorf("existing code resource = %q, want empty", codeResource)
	}
}

// assertDenylistTable checks the denylist exists with its primary key and that
// a row can be inserted, read back, and removed.
func assertDenylistTable(t *testing.T, database *sql.DB) {
	t.Helper()
	ctx := context.Background()

	expires := time.Now().UTC().Add(time.Hour)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO oauth_revoked_jti (jti, expires_at) VALUES ('jti-1', ?)`, expires); err != nil {
		t.Fatalf("insert denylist row: %v", err)
	}
	// The primary key makes revocation idempotent.
	if _, err := database.ExecContext(ctx,
		`INSERT OR IGNORE INTO oauth_revoked_jti (jti, expires_at) VALUES ('jti-1', ?)`, expires); err != nil {
		t.Fatalf("re-insert denylist row: %v", err)
	}

	var count int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oauth_revoked_jti WHERE jti = 'jti-1'`).Scan(&count); err != nil {
		t.Fatalf("count denylist row: %v", err)
	}
	if count != 1 {
		t.Errorf("denylist rows = %d, want 1", count)
	}

	if _, err := database.ExecContext(ctx, `DELETE FROM oauth_revoked_jti WHERE jti = 'jti-1'`); err != nil {
		t.Fatalf("delete denylist row: %v", err)
	}
}
