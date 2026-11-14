package db

import (
	"context"
	"database/sql"
	"io/fs"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigration025_PopulatedDatabase proves migration 025 (per-user dashboard
// pins) is safe on a database that already serves traffic:
//
//   - existing users, apps and access grants survive untouched,
//   - the new column defaults to 0, so every dashboard keeps the plain
//     name-ordered list until someone pins an app,
//   - a pin written after the upgrade survives a reopen.
func TestMigration025_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	// ── 1. Bring a fresh database to the last version before 025. ──────────
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

	// ── 2. Insert a granted app as it exists before the upgrade. ───────────
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users (id, username, email, is_admin) VALUES ('user-1', 'alice', 'alice@example.com', 0)`,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO apps (id, slug, name, host_pattern) VALUES ('app-1', 'grafana', 'Grafana', 'grafana.example.com')`,
	); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO user_app_access (user_id, app_id, role) VALUES ('user-1', 'app-1', 'member')`,
	); err != nil {
		t.Fatalf("insert access grant: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// ── 3. Upgrade exactly as a restart would. ─────────────────────────────
	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-025 database: %v", err)
	}

	var favorite int
	var role string
	if err := database.QueryRowContext(ctx,
		`SELECT favorite, role FROM user_app_access WHERE user_id = 'user-1' AND app_id = 'app-1'`,
	).Scan(&favorite, &role); err != nil {
		t.Fatalf("read access grant after upgrade: %v", err)
	}
	if favorite != 0 {
		t.Errorf("existing grant favorite = %d, want 0", favorite)
	}
	if role != "member" {
		t.Errorf("existing grant role = %q, want %q", role, "member")
	}

	// ── 4. A pin written after the upgrade survives a reopen. ──────────────
	if _, err := database.ExecContext(ctx,
		`UPDATE user_app_access SET favorite = 1 WHERE user_id = 'user-1' AND app_id = 'app-1'`,
	); err != nil {
		t.Fatalf("set favorite: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}

	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	defer database.Close()

	if err := database.QueryRowContext(ctx,
		`SELECT favorite FROM user_app_access WHERE user_id = 'user-1' AND app_id = 'app-1'`,
	).Scan(&favorite); err != nil {
		t.Fatalf("read favorite after reopen: %v", err)
	}
	if favorite != 1 {
		t.Errorf("favorite after reopen = %d, want 1", favorite)
	}
}
