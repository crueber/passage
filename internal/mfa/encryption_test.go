package mfa_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/testutil"
)

// encryptionFixture is a real in-memory database with an encrypting store and
// a service on a controllable clock.
type encryptionFixture struct {
	db      *sql.DB
	cipher  *mfa.Cipher
	store   *mfa.Store
	service *mfa.Service
	now     time.Time
}

func newEncryptionFixture(t *testing.T) *encryptionFixture {
	t.Helper()
	f := &encryptionFixture{
		db:     testutil.NewTestDB(t),
		cipher: newCipher(t, fixedKey),
		now:    time.Unix(1700000000, 0).UTC(),
	}
	f.store = mfa.NewStore(f.db, f.cipher)
	f.service = mfa.NewService(f.store, "Passage", func() time.Time { return f.now })
	return f
}

func (f *encryptionFixture) createUser(t *testing.T, id string) {
	t.Helper()
	if _, err := f.db.ExecContext(context.Background(),
		`INSERT INTO users (id, username, email) VALUES (?, ?, ?)`,
		id, id, id+"@example.com"); err != nil {
		t.Fatalf("insert user %q: %v", id, err)
	}
}

// rawSecret reads the column exactly as it sits on disk.
func (f *encryptionFixture) rawSecret(t *testing.T, userID string) string {
	t.Helper()
	var raw string
	if err := f.db.QueryRowContext(context.Background(),
		`SELECT secret FROM user_mfa WHERE user_id = ?`, userID).Scan(&raw); err != nil {
		t.Fatalf("read raw secret for %q: %v", userID, err)
	}
	return raw
}

// seedLegacyRow writes the row a pre-encryption release would have written.
func (f *encryptionFixture) seedLegacyRow(t *testing.T, userID, secret string) {
	t.Helper()
	if _, err := f.db.ExecContext(context.Background(),
		`INSERT INTO user_mfa (user_id, secret, last_step, enabled_at, created_at, updated_at)
		 VALUES (?, ?, 0, ?, ?, ?)`,
		userID, secret, f.now, f.now, f.now); err != nil {
		t.Fatalf("seed legacy mfa row for %q: %v", userID, err)
	}
}

// TestStore_EncryptsSecretAtRest is the core guarantee: the raw column never
// contains the secret, and the API still returns it.
func TestStore_EncryptsSecretAtRest(t *testing.T) {
	t.Parallel()
	f := newEncryptionFixture(t)
	ctx := context.Background()
	f.createUser(t, "alice")

	const secret = "JBSWY3DPEHPK3PXP"
	if err := f.store.UpsertPending(ctx, "alice", secret, f.now); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}

	raw := f.rawSecret(t, "alice")
	if !mfa.IsEncrypted(raw) {
		t.Fatalf("raw secret = %q; want a v1: ciphertext", raw)
	}
	if strings.Contains(raw, secret) {
		t.Fatal("raw secret contains the plaintext")
	}

	c, err := f.store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if c.Secret != secret {
		t.Errorf("Get secret = %q; want %q", c.Secret, secret)
	}
}

// TestStore_SecretIsBoundToUser moves a ciphertext onto another user's row: the
// store must refuse it rather than hand the second factor over.
func TestStore_SecretIsBoundToUser(t *testing.T) {
	t.Parallel()
	f := newEncryptionFixture(t)
	ctx := context.Background()
	f.createUser(t, "alice")
	f.createUser(t, "bob")

	if err := f.store.UpsertPending(ctx, "alice", "JBSWY3DPEHPK3PXP", f.now); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	raw := f.rawSecret(t, "alice")
	if _, err := f.db.ExecContext(ctx,
		`INSERT INTO user_mfa (user_id, secret) VALUES ('bob', ?)`, raw); err != nil {
		t.Fatalf("copy secret to bob: %v", err)
	}

	if _, err := f.store.Get(ctx, "bob"); !errors.Is(err, mfa.ErrDecrypt) {
		t.Fatalf("Get(bob) = %v; want ErrDecrypt", err)
	}
	if _, err := f.service.Verify(ctx, "bob", "123456"); err == nil {
		t.Fatal("Verify succeeded for a secret moved between users")
	}
}

// TestStore_ReencryptSecrets covers the startup upgrade pass: legacy rows are
// rewritten, already-encrypted rows are untouched, and a second run does
// nothing.
func TestStore_ReencryptSecrets(t *testing.T) {
	t.Parallel()
	f := newEncryptionFixture(t)
	ctx := context.Background()
	f.createUser(t, "alice")
	f.createUser(t, "bob")

	const legacySecret = "JBSWY3DPEHPK3PXP"
	f.seedLegacyRow(t, "alice", legacySecret)
	if err := f.store.UpsertPending(ctx, "bob", "KRSXG5DSN5UXGIDB", f.now); err != nil {
		t.Fatalf("UpsertPending: %v", err)
	}
	encryptedBefore := f.rawSecret(t, "bob")

	n, err := f.store.ReencryptSecrets(ctx)
	if err != nil {
		t.Fatalf("ReencryptSecrets: %v", err)
	}
	if n != 1 {
		t.Errorf("ReencryptSecrets changed %d rows; want 1", n)
	}

	raw := f.rawSecret(t, "alice")
	if !mfa.IsEncrypted(raw) {
		t.Fatalf("legacy secret after migration = %q; want a v1: ciphertext", raw)
	}
	if f.rawSecret(t, "bob") != encryptedBefore {
		t.Error("an already-encrypted secret was rewritten")
	}

	// The migrated row still reads as the original secret.
	c, err := f.store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get after migration: %v", err)
	}
	if c.Secret != legacySecret {
		t.Errorf("secret after migration = %q; want %q", c.Secret, legacySecret)
	}

	// Idempotent: a restart finds nothing left to do.
	n, err = f.store.ReencryptSecrets(ctx)
	if err != nil {
		t.Fatalf("ReencryptSecrets second run: %v", err)
	}
	if n != 0 {
		t.Errorf("second ReencryptSecrets changed %d rows; want 0", n)
	}
	if got := f.rawSecret(t, "alice"); got != raw {
		t.Error("second ReencryptSecrets rewrote an encrypted secret")
	}
}

func TestStore_ReencryptSecretsWithoutCipher(t *testing.T) {
	t.Parallel()
	f := newEncryptionFixture(t)
	ctx := context.Background()
	f.createUser(t, "alice")
	f.seedLegacyRow(t, "alice", "JBSWY3DPEHPK3PXP")

	store := mfa.NewStore(f.db, nil)
	n, err := store.ReencryptSecrets(ctx)
	if err != nil {
		t.Fatalf("ReencryptSecrets: %v", err)
	}
	if n != 0 {
		t.Errorf("ReencryptSecrets without a cipher changed %d rows; want 0", n)
	}
	if got := f.rawSecret(t, "alice"); got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("plaintext store rewrote the secret to %q", got)
	}
}

// TestStore_LegacySecretVerifiesCode proves the upgrade never breaks a live
// second factor: a plaintext row authenticates before the re-encryption pass
// and after it.
func TestStore_LegacySecretVerifiesCode(t *testing.T) {
	t.Parallel()
	f := newEncryptionFixture(t)
	ctx := context.Background()
	f.createUser(t, "alice")

	const legacySecret = "JBSWY3DPEHPK3PXP"
	f.seedLegacyRow(t, "alice", legacySecret)

	method, err := f.service.Verify(ctx, "alice", currentCode(t, legacySecret, f.now))
	if err != nil {
		t.Fatalf("Verify on a legacy row: %v", err)
	}
	if method != "totp" {
		t.Fatalf("method = %q; want totp", method)
	}

	if _, err := f.store.ReencryptSecrets(ctx); err != nil {
		t.Fatalf("ReencryptSecrets: %v", err)
	}

	// The enrollment step is now the watermark, so the next step is the one
	// that must verify — through the ciphertext this time.
	f.now = f.now.Add(mfa.Period)
	if _, err := f.service.Verify(ctx, "alice", currentCode(t, legacySecret, f.now)); err != nil {
		t.Fatalf("Verify after re-encryption: %v", err)
	}
}

// TestService_EnrollmentEncryptsEveryWrite drives the public service API and
// checks the stored value after both the pending write and the enable step.
func TestService_EnrollmentEncryptsEveryWrite(t *testing.T) {
	t.Parallel()
	f := newEncryptionFixture(t)
	ctx := context.Background()
	f.createUser(t, "alice")

	enr, err := f.service.BeginEnrollment(ctx, "alice", "alice")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if raw := f.rawSecret(t, "alice"); !mfa.IsEncrypted(raw) || strings.Contains(raw, enr.Secret) {
		t.Fatalf("pending raw secret = %q; want a v1: ciphertext without the plaintext", raw)
	}

	if _, err := f.service.ConfirmEnrollment(ctx, "alice", currentCode(t, enr.Secret, f.now)); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	if raw := f.rawSecret(t, "alice"); !mfa.IsEncrypted(raw) || strings.Contains(raw, enr.Secret) {
		t.Fatalf("enabled raw secret = %q; want a v1: ciphertext without the plaintext", raw)
	}

	// And the enabled factor verifies normally through the cipher.
	f.now = f.now.Add(mfa.Period)
	if _, err := f.service.Verify(ctx, "alice", currentCode(t, enr.Secret, f.now)); err != nil {
		t.Fatalf("Verify after enrollment: %v", err)
	}
}
