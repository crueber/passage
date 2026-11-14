package db_test

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/crueber/passage/internal/db"
	"github.com/crueber/passage/internal/user"
)

// TestMigration015_EmailVerificationIsSafeOnPopulatedDB proves that migration
// 015 is additive and safe on an existing deployment: rows written with the
// pre-015 column set survive, and they come back as verified (the new column
// defaults to 1, so an upgrade changes nothing for current accounts).
func TestMigration015_EmailVerificationIsSafeOnPopulatedDB(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	first, err := db.Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open (first): %v", err)
	}

	// Insert a user using only the columns that existed before migration 015.
	// Everything else (including email_verified) comes from column defaults.
	const insertUser = `
		INSERT INTO users (id, username, email, name, password_hash, is_admin, is_active, roles)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := first.ExecContext(ctx, insertUser,
		"user-1", "legacy", "legacy@example.com", "Legacy User", "hash", 0, 1, "[]",
	); err != nil {
		first.Close()
		t.Fatalf("insert legacy user: %v", err)
	}

	// Insert a verification token row so the new table's contents are proven
	// to survive a re-run of the migration set too.
	const insertToken = `
		INSERT INTO email_verification_tokens (token, user_id, email, expires_at)
		VALUES (?, ?, ?, ?)`
	expiresAt := time.Now().UTC().Add(time.Hour)
	if _, err := first.ExecContext(ctx, insertToken, "tok-1", "user-1", "legacy@example.com", expiresAt); err != nil {
		first.Close()
		t.Fatalf("insert verification token: %v", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first connection: %v", err)
	}

	// Re-open: goose sees the applied versions and does nothing, which is the
	// upgrade path a deployed instance takes.
	second, err := db.Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open (second): %v", err)
	}
	defer second.Close()

	// The column is NOT NULL with a default of 1.
	assertUserColumn(t, ctx, second, "email_verified", true, "1")

	// The legacy row is intact and reported as verified.
	store := user.NewStore(second)
	u, err := store.GetByID(ctx, "user-1")
	if err != nil {
		t.Fatalf("get legacy user after re-open: %v", err)
	}
	if u.Username != "legacy" || u.Email != "legacy@example.com" || u.Name != "Legacy User" {
		t.Errorf("legacy user changed across migration: %+v", u)
	}
	if u.PasswordHash != "hash" || u.IsAdmin || !u.IsActive || u.Roles != "[]" {
		t.Errorf("legacy user fields changed across migration: %+v", u)
	}
	if !u.EmailVerified {
		t.Error("legacy user: EmailVerified = false after upgrade, want true (default 1)")
	}

	// The token row survived.
	var tokenEmail string
	if err := second.QueryRowContext(ctx,
		`SELECT email FROM email_verification_tokens WHERE token = ?`, "tok-1",
	).Scan(&tokenEmail); err != nil {
		t.Fatalf("verification token missing after re-open: %v", err)
	}
	if tokenEmail != "legacy@example.com" {
		t.Errorf("verification token email = %q, want %q", tokenEmail, "legacy@example.com")
	}

	// Deleting the user cascades to their tokens (ON DELETE CASCADE).
	if _, err := second.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, "user-1"); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var count int
	if err := second.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM email_verification_tokens`,
	).Scan(&count); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 0 {
		t.Errorf("verification tokens after user delete = %d, want 0 (cascade)", count)
	}
}

// TestMigration015_RegistrationDefaultsToUnverifiedWhenSet proves the model
// round-trips the new flag for new rows, independent of the legacy default.
func TestMigration015_RegistrationDefaultsToUnverifiedWhenSet(t *testing.T) {
	database, err := db.Open(context.Background(), ":memory:", slog.Default())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	store := user.NewStore(database)
	u := &user.User{
		Username:      "fresh",
		Email:         "fresh@example.com",
		IsActive:      true,
		Roles:         "[]",
		EmailVerified: false,
	}
	if err := store.Create(context.Background(), u); err != nil {
		t.Fatalf("create unverified user: %v", err)
	}

	got, err := store.GetByID(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.EmailVerified {
		t.Fatal("GetByID: EmailVerified = true, want false for a row created with false")
	}

	if err := store.SetEmailVerified(context.Background(), u.ID, true); err != nil {
		t.Fatalf("SetEmailVerified: %v", err)
	}
	got, err = store.GetByID(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("get user after verify: %v", err)
	}
	if !got.EmailVerified {
		t.Fatal("GetByID after SetEmailVerified: EmailVerified = false, want true")
	}
	// The single-row update must not disturb the credential material.
	if got.Username != "fresh" || got.Email != "fresh@example.com" || got.PasswordHash != "" {
		t.Errorf("SetEmailVerified changed unrelated fields: %+v", got)
	}
}

// assertUserColumn checks a column's NOT NULL and default value in users.
func assertUserColumn(t *testing.T, ctx context.Context, database *sql.DB, column string, wantNotNull bool, wantDefault string) {
	t.Helper()

	rows, err := database.QueryContext(ctx, "PRAGMA table_info(users)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(users): %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			colType    string
			notNull    int
			dfltValue  sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &primaryKey); err != nil {
			t.Fatalf("scan column row: %v", err)
		}
		if name != column {
			continue
		}
		if (notNull != 0) != wantNotNull {
			t.Errorf("users.%s NOT NULL = %v, want %v", column, notNull != 0, wantNotNull)
		}
		if !dfltValue.Valid || dfltValue.String != wantDefault {
			t.Errorf("users.%s default = %v, want %q", column, dfltValue, wantDefault)
		}
		return
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	t.Fatalf("users.%s column not found", column)
}
