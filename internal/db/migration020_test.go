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

// TestMigration020_PopulatedDatabase proves migration 020 is safe on a database
// that is already serving traffic:
//
//   - existing rows survive,
//   - the idp_links table and its index exist afterwards,
//   - a link persists across a reopen,
//   - deleting a user cascades to their links.
//
// It builds the pre-020 schema with goose, inserts a representative user, and
// then hands the file to db.Open — the same path a deploying process takes.
func TestMigration020_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	// ── 1. Bring a fresh database to the last version before 020. ──────────
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
	if _, err := provider.UpTo(ctx, 19); err != nil {
		t.Fatalf("migrate to version 19: %v", err)
	}

	// ── 2. Insert pre-020 data. ────────────────────────────────────────────
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users (id, username, email, is_admin) VALUES ('user-1', 'alice', 'alice@example.com', 1)`,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// ── 3. Apply 020 through the production entry point. ───────────────────
	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-020 database: %v", err)
	}

	var username string
	var isAdmin int
	if err := database.QueryRowContext(ctx,
		`SELECT username, is_admin FROM users WHERE id = 'user-1'`).Scan(&username, &isAdmin); err != nil {
		t.Fatalf("read user after migration: %v", err)
	}
	if username != "alice" || isAdmin != 1 {
		t.Errorf("user after migration = (%q, %d); want (alice, 1)", username, isAdmin)
	}

	for _, name := range []string{"idp_links", "idp_links_user_id"} {
		var found int
		if err := database.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, name).Scan(&found); err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		if found != 1 {
			t.Errorf("schema object %q not found after migration", name)
		}
	}

	// ── 4. A link persists across a reopen and is unique per subject. ──────
	const insert = `INSERT INTO idp_links (id, user_id, provider, subject, email)
		VALUES (?, 'user-1', 'authentik', ?, ?)`
	if _, err := database.ExecContext(ctx, insert, "link-1", "subject-1", "alice@example.com"); err != nil {
		t.Fatalf("insert idp link: %v", err)
	}
	if _, err := database.ExecContext(ctx, insert, "link-2", "subject-1", "other@example.com"); err == nil {
		t.Error("inserting a duplicate (provider, subject) link succeeded; want UNIQUE violation")
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}

	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	defer database.Close()

	var links int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM idp_links`).Scan(&links); err != nil {
		t.Fatalf("count idp_links: %v", err)
	}
	if links != 1 {
		t.Errorf("idp_links rows after reopen = %d; want 1", links)
	}

	// ── 5. Deleting a user cascades to their links. ────────────────────────
	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 'user-1'`); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM idp_links`).Scan(&links); err != nil {
		t.Fatalf("count idp_links after delete: %v", err)
	}
	if links != 0 {
		t.Errorf("idp_links kept %d rows after the user was deleted", links)
	}
}
