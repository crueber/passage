package db_test

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/db"
)

// TestMigration034_PerformanceIndexes verifies that migration 034 creates all
// expected hot-path/sweep indexes, that SQLite's query planner uses them on
// every sweep query (verified via EXPLAIN QUERY PLAN), that synchronous=FULL
// and foreign_keys=1 are enforced, and that reopening an existing DB succeeds.
func TestMigration034_PerformanceIndexes(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "passage.db")
	ctx := context.Background()

	database, err := db.Open(ctx, dbPath, slog.Default())
	if err != nil {
		t.Fatalf("first db.Open: %v", err)
	}

	wantIndexes := []string{
		"idx_webauthn_credentials_user_id",
		"idx_mfa_challenges_expires_at",
		"idx_password_reset_tokens_user_id",
		"idx_password_reset_tokens_expires_at",
		"idx_password_reset_tokens_used",
		"idx_magic_link_tokens_used",
		"idx_email_verification_tokens_expires_at",
		"idx_email_verification_tokens_used",
		"idx_invitations_pending_expires_at",
	}
	for _, idx := range wantIndexes {
		var name string
		err := database.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, idx,
		).Scan(&name)
		if err != nil {
			t.Errorf("index %q not found: %v", idx, err)
		}
	}

	// Verify foreign_keys=1 and synchronous=FULL (2) are enforced via DSN.
	var fk, syncMode int
	if err := database.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("PRAGMA foreign_keys = %d, want 1", fk)
	}
	if err := database.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&syncMode); err != nil {
		t.Fatalf("PRAGMA synchronous: %v", err)
	}
	if syncMode != 2 { // 2 = FULL
		t.Errorf("PRAGMA synchronous = %d, want 2 (FULL)", syncMode)
	}

	// Verify via EXPLAIN QUERY PLAN that every hot-path lookup and cleanup sweep
	// uses an index rather than falling back to a full table SCAN.
	now := time.Now().UTC()
	planCases := []struct {
		name      string
		query     string
		args      []any
		wantIndex string
	}{
		{
			name:      "webauthn credentials by user",
			query:     `SELECT id FROM webauthn_credentials WHERE user_id = ?`,
			args:      []any{"u1"},
			wantIndex: "idx_webauthn_credentials_user_id",
		},
		{
			name:      "mfa challenges expiry sweep",
			query:     `DELETE FROM mfa_challenges WHERE expires_at < ?`,
			args:      []any{now},
			wantIndex: "idx_mfa_challenges_expires_at",
		},
		{
			name:      "password reset tokens expiry sweep",
			query:     `DELETE FROM password_reset_tokens WHERE expires_at < ?`,
			args:      []any{now},
			wantIndex: "idx_password_reset_tokens_expires_at",
		},
		{
			name:      "password reset tokens used sweep",
			query:     `DELETE FROM password_reset_tokens WHERE used_at IS NOT NULL`,
			wantIndex: "idx_password_reset_tokens_used",
		},
		{
			name:      "magic link tokens used sweep",
			query:     `DELETE FROM magic_link_tokens WHERE used_at IS NOT NULL`,
			wantIndex: "idx_magic_link_tokens_used",
		},
		{
			name:      "email verification tokens expiry sweep",
			query:     `DELETE FROM email_verification_tokens WHERE expires_at < ?`,
			args:      []any{now},
			wantIndex: "idx_email_verification_tokens_expires_at",
		},
		{
			name:      "email verification tokens used sweep",
			query:     `DELETE FROM email_verification_tokens WHERE used_at IS NOT NULL`,
			wantIndex: "idx_email_verification_tokens_used",
		},
		{
			name:      "invitations expired pending sweep",
			query:     `DELETE FROM invitations WHERE accepted_at IS NULL AND expires_at < ?`,
			args:      []any{now},
			wantIndex: "idx_invitations_pending_expires_at",
		},
	}

	for _, tc := range planCases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := database.QueryContext(ctx, "EXPLAIN QUERY PLAN "+tc.query, tc.args...)
			if err != nil {
				t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
			}
			defer rows.Close()

			var details []string
			for rows.Next() {
				var id, parent, notused int
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					t.Fatalf("scan plan: %v", err)
				}
				details = append(details, detail)
			}
			plan := strings.Join(details, "; ")
			if !strings.Contains(plan, tc.wantIndex) {
				t.Errorf("plan = %q, want index %q", plan, tc.wantIndex)
			}
		})
	}

	if err := database.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	// Reopening an already-migrated database must succeed cleanly.
	reopened, err := db.Open(ctx, dbPath, slog.Default())
	if err != nil {
		t.Fatalf("reopen db.Open: %v", err)
	}
	defer reopened.Close()
}
