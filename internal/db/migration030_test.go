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

// TestMigration030_PopulatedDatabase proves the per-account theme column is
// safe on a live database: existing users survive and default to the server
// theme (an empty override).
func TestMigration030_PopulatedDatabase(t *testing.T) {
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
	if _, err := provider.UpTo(ctx, 29); err != nil {
		t.Fatalf("migrate to version 29: %v", err)
	}

	if _, err := raw.ExecContext(ctx, `
		INSERT INTO users (id, username, email, password_hash, is_admin, is_active)
		VALUES ('user-1', 'existing', 'existing@example.com', 'hash', 1, 1)`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-030 database: %v", err)
	}
	defer database.Close()

	var username, theme string
	if err := database.QueryRowContext(ctx,
		`SELECT username, theme FROM users WHERE id = 'user-1'`).Scan(&username, &theme); err != nil {
		t.Fatalf("read existing user: %v", err)
	}
	if username != "existing" {
		t.Errorf("username = %q, want unchanged", username)
	}
	if theme != "" {
		t.Errorf("theme = %q, want empty (follow the server default)", theme)
	}

	// The column accepts a registered slug and survives a reopen.
	if _, err := database.ExecContext(ctx,
		`UPDATE users SET theme = 'nord' WHERE id = 'user-1'`); err != nil {
		t.Fatalf("set theme: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}

	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT theme FROM users WHERE id = 'user-1'`).Scan(&theme); err != nil {
		t.Fatalf("read theme after reopen: %v", err)
	}
	if theme != "nord" {
		t.Errorf("theme after reopen = %q, want nord", theme)
	}
}
