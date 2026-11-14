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

// TestMigration028_PopulatedDatabase proves the upstream-provider migration is
// safe on a live database: it only adds a table, existing data is untouched,
// and a restart does not disturb rows an operator later adds.
func TestMigration028_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	raw.SetMaxOpenConns(1)

	migrationsFS, err := fs.Sub(migrations, "migrations")
	if err != nil {
		t.Fatalf("create migrations sub-fs: %v", err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, raw, migrationsFS, goose.WithSlog(logger))
	if err != nil {
		t.Fatalf("create migration provider: %v", err)
	}
	if _, err := provider.UpTo(ctx, 27); err != nil {
		t.Fatalf("migrate to version 27: %v", err)
	}

	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users (id, username, email, is_admin) VALUES ('user-1', 'alice', 'alice@example.com', 1)`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO apps (id, slug, name, host_pattern) VALUES ('app-1', 'grafana', 'Grafana', 'grafana.example.com')`); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-028 database: %v", err)
	}

	var users, apps, providers int
	for query, dest := range map[string]*int{
		`SELECT COUNT(*) FROM users`:         &users,
		`SELECT COUNT(*) FROM apps`:          &apps,
		`SELECT COUNT(*) FROM idp_providers`: &providers,
	} {
		if err := database.QueryRowContext(ctx, query).Scan(dest); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	if users != 1 || apps != 1 || providers != 0 {
		t.Fatalf("after upgrade users=%d apps=%d providers=%d", users, apps, providers)
	}

	// A provider added after the upgrade survives a restart.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO idp_providers (id, name, issuer, client_id, client_secret)
		 VALUES ('p1', 'authentik', 'https://auth.example.com/', 'passage', 'sealed')`); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}

	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	defer database.Close()

	var name string
	if err := database.QueryRowContext(ctx, `SELECT name FROM idp_providers WHERE id = 'p1'`).Scan(&name); err != nil {
		t.Fatalf("read provider after reopen: %v", err)
	}
	if name != "authentik" {
		t.Errorf("provider name after reopen = %q", name)
	}
}
