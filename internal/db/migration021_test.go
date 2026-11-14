package db

import (
	"context"
	"database/sql"
	"io/fs"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

// TestMigration021_PopulatedDatabase proves migration 021 (per-app access
// policies) is safe on a database that is already serving traffic:
//
//   - every existing row survives with its data intact,
//   - the new apps columns exist and default to "no restriction" for rows that
//     predate the migration,
//   - an app created before the feature keeps working: its policy is empty,
//   - policy values persist across a reopen, and re-opening is a no-op.
//
// It builds the pre-021 schema with goose (up to 019 — 020 belongs to another
// branch and is deliberately absent, which also exercises the out-of-order
// migration support), inserts representative rows, and then hands the file to
// db.Open — the same path a deploying process takes.
func TestMigration021_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	// ── 1. Bring a fresh database to the last version before 021. ──────────
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

	// ── 2. Insert representative pre-021 data. ─────────────────────────────
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users (id, username, email, is_admin) VALUES ('user-1', 'alice', 'alice@example.com', 1)`,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO apps (id, slug, name, host_pattern, is_active) VALUES ('app-1', 'grafana', 'Grafana', 'grafana.example.com', 1)`,
	); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO apps (id, slug, name, host_pattern, is_active) VALUES ('app-2', 'gitea', 'Gitea', 'gitea.example.com', 0)`,
	); err != nil {
		t.Fatalf("insert second app: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		 VALUES ('session-1', 'public-1', 'user-1', 'app-1', '192.0.2.1', 'Agent/1', ?, ?)`,
		created.Add(24*time.Hour), created,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// ── 3. Apply 021 through the production entry point. ───────────────────
	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-021 database: %v", err)
	}

	// Existing data is untouched and the pre-existing apps keep working with a
	// policy that imposes nothing.
	var (
		slug      string
		host      string
		requiredG string
		requiredR string
		cidrs     string
		hours     string
		days      string
		adminOnly int
	)
	if err := database.QueryRowContext(ctx,
		`SELECT slug, host_pattern, required_group, required_role, allowed_cidrs,
		        allowed_hours, allowed_days, admin_only
		 FROM apps WHERE id = 'app-1'`).
		Scan(&slug, &host, &requiredG, &requiredR, &cidrs, &hours, &days, &adminOnly); err != nil {
		t.Fatalf("read app after migration: %v", err)
	}
	if slug != "grafana" || host != "grafana.example.com" {
		t.Errorf("app after migration = (%q, %q); want (grafana, grafana.example.com)", slug, host)
	}
	if requiredG != "" || requiredR != "" || cidrs != "" || hours != "" || days != "" || adminOnly != 0 {
		t.Errorf("policy defaults after migration = (%q, %q, %q, %q, %q, %d); want all empty/0",
			requiredG, requiredR, cidrs, hours, days, adminOnly)
	}

	var sessions int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 1 {
		t.Errorf("sessions after migration = %d; want 1", sessions)
	}

	// ── 4. Policy values persist across a reopen. ──────────────────────────
	if _, err := database.ExecContext(ctx,
		`UPDATE apps SET required_group = 'platform', required_role = 'ops',
		        allowed_cidrs = '10.0.0.0/8', admin_only = 1,
		        allowed_hours = '09:00-17:00', allowed_days = '1-5'
		 WHERE id = 'app-1'`); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}

	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	defer database.Close()

	var (
		gotGroup string
		gotRole  string
		gotCIDRs string
		gotHours string
		gotDays  string
		gotAdmin int
	)
	if err := database.QueryRowContext(ctx,
		`SELECT required_group, required_role, allowed_cidrs, allowed_hours, allowed_days, admin_only
		 FROM apps WHERE id = 'app-1'`).
		Scan(&gotGroup, &gotRole, &gotCIDRs, &gotHours, &gotDays, &gotAdmin); err != nil {
		t.Fatalf("read policy after reopen: %v", err)
	}
	if gotGroup != "platform" || gotRole != "ops" || gotCIDRs != "10.0.0.0/8" ||
		gotHours != "09:00-17:00" || gotDays != "1-5" || gotAdmin != 1 {
		t.Errorf("policy after reopen = (%q, %q, %q, %q, %q, %d); want the stored values",
			gotGroup, gotRole, gotCIDRs, gotHours, gotDays, gotAdmin)
	}

	// The second, inactive app still has an empty policy.
	var otherGroup string
	if err := database.QueryRowContext(ctx,
		`SELECT required_group FROM apps WHERE id = 'app-2'`).Scan(&otherGroup); err != nil {
		t.Fatalf("read second app: %v", err)
	}
	if otherGroup != "" {
		t.Errorf("second app required_group = %q, want empty", otherGroup)
	}
}
