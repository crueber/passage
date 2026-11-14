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

// TestMigration029_PopulatedDatabase proves the invitations migration is safe
// on a live database: existing users and their credentials survive, and the
// new table is usable immediately after the upgrade.
func TestMigration029_PopulatedDatabase(t *testing.T) {
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
	if _, err := provider.UpTo(ctx, 28); err != nil {
		t.Fatalf("migrate to version 28: %v", err)
	}

	// A populated pre-029 database: one user with a password hash.
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
		t.Fatalf("db.Open after populated pre-029 database: %v", err)
	}
	defer database.Close()

	var username, passwordHash string
	if err := database.QueryRowContext(ctx,
		`SELECT username, password_hash FROM users WHERE id = 'user-1'`).Scan(&username, &passwordHash); err != nil {
		t.Fatalf("read existing user: %v", err)
	}
	if username != "existing" || passwordHash != "hash" {
		t.Errorf("existing user = %q/%q, want unchanged username and hash", username, passwordHash)
	}

	// The table accepts a row with the columns the store writes.
	if _, err := database.ExecContext(ctx, `
		INSERT INTO invitations (id, token, email, name, invited_by, expires_at)
		VALUES ('inv-1', 'token-1', 'new@example.com', 'New User', 'admin', datetime('now', '+7 days'))`); err != nil {
		t.Fatalf("insert invitation: %v", err)
	}

	// One live invitation per address is enforced by the partial index.
	if _, err := database.ExecContext(ctx, `
		INSERT INTO invitations (id, token, email, name, invited_by, expires_at)
		VALUES ('inv-2', 'token-2', 'new@example.com', '', 'admin', datetime('now', '+7 days'))`); err == nil {
		t.Error("second pending invitation for one address was accepted; want a unique-index error")
	}
}
