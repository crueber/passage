package db_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/crueber/passage/internal/db"
)

func TestOpen_CreatesSchema(t *testing.T) {
	database, err := db.Open(context.Background(), ":memory:", slog.Default())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	// Verify each expected table exists in sqlite_master.
	tables := []string{
		"users",
		"apps",
		"user_app_access",
		"sessions",
		"password_reset_tokens",
		"webauthn_credentials",
		"settings",
		// OAuth tables added in migration 002.
		"oauth_codes",
		"oauth_tokens",
		"oauth_refresh_tokens",
		"oidc_config",
	}

	for _, table := range tables {
		t.Run(table, func(t *testing.T) {
			var name string
			err := database.QueryRowContext(
				context.Background(),
				"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
				table,
			).Scan(&name)
			if err != nil {
				t.Errorf("table %q not found in schema: %v", table, err)
			}
		})
	}
}

func TestOpen_OAuthColumnsInApps(t *testing.T) {
	database, err := db.Open(context.Background(), ":memory:", slog.Default())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	// Query all column names in the apps table.
	rows, err := database.QueryContext(context.Background(), "PRAGMA table_info(apps)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(apps): %v", err)
	}
	defer rows.Close()

	colNames := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, dfltValue, pk any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan column row: %v", err)
		}
		colNames[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}

	// Verify the 4 OAuth columns added by migration 002 are present.
	oauthColumns := []string{
		"client_id",
		"client_secret_hash",
		"redirect_uris",
		"oauth_enabled",
	}
	for _, col := range oauthColumns {
		t.Run(col, func(t *testing.T) {
			if !colNames[col] {
				t.Errorf("column %q not found in apps table", col)
			}
		})
	}
}

func TestOpen_WALEnabled(t *testing.T) {
	// Use a temporary file-based DB to properly test WAL mode.
	// In-memory SQLite databases use "memory" journal mode, not "wal".
	dir := t.TempDir()
	path := dir + "/test.db"

	database, err := db.Open(context.Background(), path, slog.Default())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	var journalMode string
	if err := database.QueryRowContext(context.Background(), "PRAGMA journal_mode;").Scan(&journalMode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}

	if journalMode != "wal" {
		t.Errorf("journal_mode = %q; want %q", journalMode, "wal")
	}
}

func TestOpen_ForeignKeysEnabled(t *testing.T) {
	database, err := db.Open(context.Background(), ":memory:", slog.Default())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	var fkEnabled int
	if err := database.QueryRowContext(context.Background(), "PRAGMA foreign_keys;").Scan(&fkEnabled); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}

	if fkEnabled != 1 {
		t.Errorf("foreign_keys = %d; want 1", fkEnabled)
	}
}
