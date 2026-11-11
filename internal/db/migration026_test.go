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

// TestMigration026_PopulatedDatabase proves the sign-in tagline migration is
// safe on a live database: it only adds one setting, keeps everything else,
// and never overwrites a value the operator has since edited.
func TestMigration026_PopulatedDatabase(t *testing.T) {
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
	if _, err := provider.UpTo(ctx, 25); err != nil {
		t.Fatalf("migrate to version 25: %v", err)
	}

	// A representative settings row, plus one the operator already customised.
	if _, err := raw.ExecContext(ctx,
		`UPDATE settings SET value = 'false' WHERE key = 'allow_registration'`); err != nil {
		t.Fatalf("customise allow_registration: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-026 database: %v", err)
	}

	var tagline string
	if err := database.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = 'login_tagline'`).Scan(&tagline); err != nil {
		t.Fatalf("read login_tagline: %v", err)
	}
	if want := "Self-hosted authentication for your home lab"; tagline != want {
		t.Errorf("login_tagline = %q, want %q", tagline, want)
	}

	var registration string
	if err := database.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = 'allow_registration'`).Scan(&registration); err != nil {
		t.Fatalf("read allow_registration: %v", err)
	}
	if registration != "false" {
		t.Errorf("allow_registration = %q, want the stored value %q", registration, "false")
	}

	// An edited tagline survives a restart: the seed is INSERT OR IGNORE.
	if _, err := database.ExecContext(ctx,
		`UPDATE settings SET value = 'Welcome to the lab' WHERE key = 'login_tagline'`); err != nil {
		t.Fatalf("customise login_tagline: %v", err)
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
		`SELECT value FROM settings WHERE key = 'login_tagline'`).Scan(&tagline); err != nil {
		t.Fatalf("read login_tagline after reopen: %v", err)
	}
	if tagline != "Welcome to the lab" {
		t.Errorf("login_tagline after reopen = %q, want the edited value", tagline)
	}
}
