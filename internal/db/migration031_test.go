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

// TestMigration031_ThemeRenames proves the slug rename reaches both stored
// places: the server default and a per-user override.
func TestMigration031_ThemeRenames(t *testing.T) {
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
	if _, err := provider.UpTo(ctx, 30); err != nil {
		t.Fatalf("migrate to version 30: %v", err)
	}

	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users (id, username, email, password_hash, is_admin, is_active, theme)
		 VALUES ('user-1', 'existing', 'existing@example.com', 'hash', 1, 1, 'nord')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`UPDATE settings SET value = 'slate' WHERE key = 'ui_theme'`); err != nil {
		t.Fatalf("set legacy default: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-031 database: %v", err)
	}
	defer database.Close()

	var defaultTheme, userTheme string
	if err := database.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = 'ui_theme'`).Scan(&defaultTheme); err != nil {
		t.Fatalf("read ui_theme: %v", err)
	}
	if defaultTheme != "cool-slate" {
		t.Errorf("ui_theme = %q, want cool-slate", defaultTheme)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT theme FROM users WHERE id = 'user-1'`).Scan(&userTheme); err != nil {
		t.Fatalf("read user theme: %v", err)
	}
	if userTheme != "arctic-blue" {
		t.Errorf("user theme = %q, want arctic-blue", userTheme)
	}
}
