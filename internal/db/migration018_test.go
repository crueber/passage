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

// TestMigration018_PopulatedDatabase proves migration 018 is safe to apply to a
// database that already holds live sessions:
//
//   - every existing row survives with its data intact,
//   - last_used_at is backfilled from created_at (never left NULL),
//   - re-opening the database is a no-op.
//
// It builds the pre-018 schema with goose directly, inserts representative
// rows, then hands the file to db.Open — the same path a deploying process
// takes.
func TestMigration018_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	// ── 1. Bring a fresh database to the last version before 018. ──────────
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
	applied, err := provider.UpTo(ctx, 17)
	if err != nil {
		t.Fatalf("migrate to version 17: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("expected at least one migration before 018")
	}

	// ── 2. Insert representative pre-018 data. ─────────────────────────────
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	expires := created.Add(24 * time.Hour)

	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users (id, username, email) VALUES ('user-1', 'alice', 'alice@example.com')`,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO apps (id, slug, name, host_pattern) VALUES ('app-1', 'grafana', 'Grafana', 'grafana.example.com')`,
	); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	const insertSession = `INSERT INTO sessions
		(id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		VALUES (?, ?, 'user-1', ?, ?, ?, ?, ?)`
	if _, err := raw.ExecContext(ctx, insertSession,
		"session-plain", "public-plain", nil, "192.0.2.1", "Agent/1", expires, created,
	); err != nil {
		t.Fatalf("insert plain session: %v", err)
	}
	if _, err := raw.ExecContext(ctx, insertSession,
		"session-app", "public-app", "app-1", "192.0.2.2", "Agent/2", expires, created,
	); err != nil {
		t.Fatalf("insert app session: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// ── 3. Apply 018 through the production entry point. ───────────────────
	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-018 database: %v", err)
	}
	defer database.Close()

	assertMigration018State(t, database, created, expires)

	// ── 4. Re-running migrations on the migrated database changes nothing. ─
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}
	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open second time: %v", err)
	}
	assertMigration018State(t, database, created, expires)
}

// assertMigration018State checks the columns, index, and rows survive the
// migration with last_used_at backfilled from created_at.
func assertMigration018State(t *testing.T, database *sql.DB, created, expires time.Time) {
	t.Helper()
	ctx := context.Background()

	var hasColumn bool
	rows, err := database.QueryContext(ctx, "PRAGMA table_info(sessions)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(sessions): %v", err)
	}
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, dfltValue, pk any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		if name == "last_used_at" {
			hasColumn = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}
	rows.Close()
	if !hasColumn {
		t.Fatal("sessions.last_used_at was not added")
	}

	var hasIndex bool
	if err := database.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='sessions_last_used_at')`,
	).Scan(&hasIndex); err != nil {
		t.Fatalf("query index: %v", err)
	}
	if hasIndex {
		t.Error("sessions_last_used_at index should not be created (the idle sweep cannot use it)")
	}

	const query = `SELECT id, public_id, app_id, ip_address, user_agent, expires_at, created_at, last_used_at
		FROM sessions ORDER BY id`
	rows, err = database.QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	defer rows.Close()

	type row struct {
		id, publicID, ip, ua string
		appID                sql.NullString
		expiresAt, createdAt time.Time
		lastUsedAt           sql.NullTime
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.publicID, &r.appID, &r.ip, &r.ua, &r.expiresAt, &r.createdAt, &r.lastUsedAt); err != nil {
			t.Fatalf("scan session: %v", err)
		}
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("session rows: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("session rows after migration = %d, want 2", len(got))
	}

	want := map[string]struct {
		publicID string
		appID    sql.NullString
		ip       string
	}{
		"session-plain": {"public-plain", sql.NullString{}, "192.0.2.1"},
		"session-app":   {"public-app", sql.NullString{String: "app-1", Valid: true}, "192.0.2.2"},
	}
	for _, r := range got {
		w, ok := want[r.id]
		if !ok {
			t.Errorf("unexpected session row %q", r.id)
			continue
		}
		if r.publicID != w.publicID {
			t.Errorf("%s: public_id = %q, want %q", r.id, r.publicID, w.publicID)
		}
		if r.ip != w.ip {
			t.Errorf("%s: ip_address = %q, want %q", r.id, r.ip, w.ip)
		}
		if r.appID != w.appID {
			t.Errorf("%s: app_id = %v, want %v", r.id, r.appID, w.appID)
		}
		if !r.expiresAt.Equal(expires) {
			t.Errorf("%s: expires_at = %v, want %v", r.id, r.expiresAt, expires)
		}
		if !r.createdAt.Equal(created) {
			t.Errorf("%s: created_at changed: %v, want %v", r.id, r.createdAt, created)
		}
		if !r.lastUsedAt.Valid {
			t.Errorf("%s: last_used_at is NULL after backfill", r.id)
			continue
		}
		if !r.lastUsedAt.Time.Equal(created) {
			t.Errorf("%s: last_used_at = %v, want created_at %v", r.id, r.lastUsedAt.Time, created)
		}
	}
}
