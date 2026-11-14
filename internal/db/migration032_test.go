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

// TestMigration032_AppView proves the per-account app-view column is safe on a
// populated database and defaults to empty (Comfortable).
func TestMigration032_AppView(t *testing.T) {
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
	if _, err := provider.UpTo(ctx, 31); err != nil {
		t.Fatalf("migrate to version 31: %v", err)
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
		t.Fatalf("db.Open after populated pre-032 database: %v", err)
	}
	defer database.Close()

	var view string
	if err := database.QueryRowContext(ctx,
		`SELECT app_view FROM users WHERE id = 'user-1'`).Scan(&view); err != nil {
		t.Fatalf("read app_view: %v", err)
	}
	if view != "" {
		t.Errorf("app_view = %q, want empty (Comfortable)", view)
	}

	if _, err := database.ExecContext(ctx,
		`UPDATE users SET app_view = 'iconized' WHERE id = 'user-1'`); err != nil {
		t.Fatalf("set app_view: %v", err)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT app_view FROM users WHERE id = 'user-1'`).Scan(&view); err != nil {
		t.Fatalf("read app_view after update: %v", err)
	}
	if view != "iconized" {
		t.Errorf("app_view after update = %q, want iconized", view)
	}
}
