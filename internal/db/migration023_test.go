package db

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"io/fs"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/crueber/passage/internal/oauth"
)

// TestMigration023_PopulatedDatabase proves migration 023 (OIDC signing keys
// with kid history) is safe on a database that already serves traffic:
//
//   - every existing user, app, session, and audit row survives untouched,
//   - the previous single RSA key in oidc_config survives untouched, so a
//     rollback to an older binary still finds it,
//   - oauth_signing_keys is created empty: importing the legacy key is a
//     startup step, not a migration step,
//   - the startup import runs once, derives the same kid as before, and is
//     idempotent across a reopen.
func TestMigration023_PopulatedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "passage.db")
	logger := slog.New(slog.DiscardHandler)

	// ── 1. Bring a fresh database to the last version before 023. ──────────
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
	if _, err := provider.UpTo(ctx, 22); err != nil {
		t.Fatalf("migrate to version 22: %v", err)
	}

	// ── 2. Insert representative pre-023 data, including the legacy RSA key. ─
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users (id, username, email, is_admin) VALUES ('user-1', 'alice', 'alice@example.com', 1)`,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO apps (id, slug, name, host_pattern) VALUES ('app-1', 'grafana', 'Grafana', 'grafana.example.com')`,
	); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		 VALUES ('session-1', 'public-1', 'user-1', 'app-1', '192.0.2.1', 'Agent/1', ?, ?)`,
		created.Add(24*time.Hour), created,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO audit_log (id, actor_id, actor_name, action) VALUES ('audit-1', 'user-1', 'alice', 'user.create')`,
	); err != nil {
		t.Fatalf("insert audit row: %v", err)
	}

	legacyPEM, wantKID := newLegacyKey(t)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO oidc_config (key, value, created_at, updated_at) VALUES ('rsa_private_key', ?, ?, ?)`,
		string(legacyPEM), created, created,
	); err != nil {
		t.Fatalf("insert legacy oidc_config key: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// ── 3. Apply 023 through the production entry point. ───────────────────
	database, err := Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open after populated pre-023 database: %v", err)
	}
	defer database.Close()

	assertPre023DataIntact(t, database)
	assertSigningKeysSchema(t, database)

	// The migration creates the table but does not import the key: that is the
	// startup step below, which keeps a migration free of crypto.
	var count int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_signing_keys`).Scan(&count); err != nil {
		t.Fatalf("count oauth_signing_keys: %v", err)
	}
	if count != 0 {
		t.Errorf("oauth_signing_keys rows after migration = %d, want 0", count)
	}

	// ── 4. The startup import runs once with the derived kid. ──────────────
	store := oauth.NewStore(database)
	if err := store.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys: %v", err)
	}
	assertImportedKey(t, database, wantKID, legacyPEM)

	// ── 5. Reopening the database does not import again. ───────────────────
	if err := database.Close(); err != nil {
		t.Fatalf("close migrated db: %v", err)
	}
	database, err = Open(ctx, path, logger)
	if err != nil {
		t.Fatalf("db.Open on an already-migrated database: %v", err)
	}
	if err := oauth.NewStore(database).EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys after reopen: %v", err)
	}
	assertImportedKey(t, database, wantKID, legacyPEM)
	assertPre023DataIntact(t, database)
}

// assertImportedKey checks exactly one signing key exists, it is the legacy
// key, its kid is the derived one, and the legacy oidc_config row is untouched.
func assertImportedKey(t *testing.T, database *sql.DB, wantKID string, legacyPEM []byte) {
	t.Helper()
	ctx := context.Background()

	var (
		count  int
		kid    string
		pemStr string
	)
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*), kid, private_key_pem FROM oauth_signing_keys`,
	).Scan(&count, &kid, &pemStr); err != nil {
		t.Fatalf("read imported signing key: %v", err)
	}
	if count != 1 {
		t.Fatalf("oauth_signing_keys rows = %d, want 1", count)
	}
	if kid != wantKID {
		t.Errorf("imported kid = %q, want derived %q", kid, wantKID)
	}
	if pemStr != string(legacyPEM) {
		t.Error("imported PEM differs from the legacy PEM")
	}

	var legacyStored string
	if err := database.QueryRowContext(ctx,
		`SELECT value FROM oidc_config WHERE key = 'rsa_private_key'`).Scan(&legacyStored); err != nil {
		t.Fatalf("read legacy oidc_config key: %v", err)
	}
	if legacyStored != string(legacyPEM) {
		t.Error("the legacy oidc_config row was modified; rollback would break")
	}
}

// assertPre023DataIntact checks the rows written before the migration are
// untouched.
func assertPre023DataIntact(t *testing.T, database *sql.DB) {
	t.Helper()
	ctx := context.Background()

	var (
		username string
		isAdmin  int
	)
	if err := database.QueryRowContext(ctx,
		`SELECT username, is_admin FROM users WHERE id = 'user-1'`).Scan(&username, &isAdmin); err != nil {
		t.Fatalf("read user after migration: %v", err)
	}
	if username != "alice" || isAdmin != 1 {
		t.Errorf("user after migration = (%q, %d); want (alice, 1)", username, isAdmin)
	}

	var slug string
	if err := database.QueryRowContext(ctx,
		`SELECT slug FROM apps WHERE id = 'app-1'`).Scan(&slug); err != nil {
		t.Fatalf("read app after migration: %v", err)
	}
	if slug != "grafana" {
		t.Errorf("app slug after migration = %q, want grafana", slug)
	}

	for _, q := range []struct {
		name  string
		query string
	}{
		{"sessions", `SELECT COUNT(*) FROM sessions WHERE id = 'session-1'`},
		{"audit_log", `SELECT COUNT(*) FROM audit_log WHERE id = 'audit-1'`},
	} {
		var n int
		if err := database.QueryRowContext(ctx, q.query).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", q.name, err)
		}
		if n != 1 {
			t.Errorf("%s row after migration = %d, want 1", q.name, n)
		}
	}
}

// assertSigningKeysSchema checks the new table has exactly the expected columns.
func assertSigningKeysSchema(t *testing.T, database *sql.DB) {
	t.Helper()

	rows, err := database.QueryContext(context.Background(), "PRAGMA table_info(oauth_signing_keys)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(oauth_signing_keys): %v", err)
	}
	defer rows.Close()

	want := map[string]bool{
		"kid":             false,
		"private_key_pem": false,
		"created_at":      false,
		"retired_at":      false,
	}
	for rows.Next() {
		var (
			cid       int
			name      string
			colType   string
			notNull   any
			dfltValue any
			pk        any
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan column row: %v", err)
		}
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}

	for name, found := range want {
		if !found {
			t.Errorf("oauth_signing_keys.%s is missing", name)
		}
	}
}

// newLegacyKey returns a PKCS#1 PEM and the kid the production derivation
// computes for it.
func newLegacyKey(t *testing.T) ([]byte, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate legacy key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal legacy public key: %v", err)
	}
	sum := sha256.Sum256(pubDER)
	return pemBytes, base64.RawURLEncoding.EncodeToString(sum[:])
}
