package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/crueber/passage/internal/db"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/testutil"
)

func TestSQLiteStore_Code(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	// Seed a user and app so FK constraints are satisfied.
	appID, userID := seedAppAndUser(t, db)

	t.Run("CreateCode", func(t *testing.T) {
		c := &oauth.Code{
			AppID:       appID,
			UserID:      userID,
			RedirectURI: "https://example.com/callback",
			Scopes:      "openid profile",
			ExpiresAt:   time.Now().UTC().Add(10 * time.Minute),
		}
		if err := store.CreateCode(ctx, c); err != nil {
			t.Fatalf("CreateCode: %v", err)
		}
		if c.Code == "" {
			t.Fatal("CreateCode: code not assigned")
		}
		if c.CreatedAt.IsZero() {
			t.Fatal("CreateCode: created_at not assigned")
		}
	})

	t.Run("GetCode_Found", func(t *testing.T) {
		c := &oauth.Code{
			AppID:       appID,
			UserID:      userID,
			RedirectURI: "https://example.com/callback",
			Scopes:      "openid",
			ExpiresAt:   time.Now().UTC().Add(10 * time.Minute),
		}
		if err := store.CreateCode(ctx, c); err != nil {
			t.Fatalf("CreateCode: %v", err)
		}

		got, err := store.GetCode(ctx, c.Code)
		if err != nil {
			t.Fatalf("GetCode: %v", err)
		}
		if got.Code != c.Code {
			t.Errorf("GetCode code: got %q, want %q", got.Code, c.Code)
		}
		if got.AppID != appID {
			t.Errorf("GetCode app_id: got %q, want %q", got.AppID, appID)
		}
		if got.UserID != userID {
			t.Errorf("GetCode user_id: got %q, want %q", got.UserID, userID)
		}
		if got.UsedAt != nil {
			t.Errorf("GetCode used_at: expected nil, got %v", got.UsedAt)
		}
	})

	t.Run("GetCode_NotFound", func(t *testing.T) {
		_, err := store.GetCode(ctx, "nonexistent-code-xyz")
		if !errors.Is(err, oauth.ErrCodeNotFound) {
			t.Errorf("GetCode not found: got %v, want ErrCodeNotFound", err)
		}
	})

	t.Run("MarkCodeUsed", func(t *testing.T) {
		c := &oauth.Code{
			AppID:       appID,
			UserID:      userID,
			RedirectURI: "https://example.com/callback",
			Scopes:      "openid",
			ExpiresAt:   time.Now().UTC().Add(10 * time.Minute),
		}
		if err := store.CreateCode(ctx, c); err != nil {
			t.Fatalf("CreateCode: %v", err)
		}

		if err := store.MarkCodeUsed(ctx, c.Code); err != nil {
			t.Fatalf("MarkCodeUsed: %v", err)
		}

		got, err := store.GetCode(ctx, c.Code)
		if err != nil {
			t.Fatalf("GetCode after MarkCodeUsed: %v", err)
		}
		if got.UsedAt == nil {
			t.Error("GetCode after MarkCodeUsed: expected UsedAt to be set")
		}
	})

	t.Run("with_pkce_s256", func(t *testing.T) {
		challenge := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // 43-char base64url string
		c := &oauth.Code{
			AppID:               appID,
			UserID:              userID,
			RedirectURI:         "https://example.com/callback",
			Scopes:              "openid",
			ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
			CodeChallenge:       challenge,
			CodeChallengeMethod: oauth.PKCEMethodS256,
		}
		if err := store.CreateCode(ctx, c); err != nil {
			t.Fatalf("CreateCode with PKCE: %v", err)
		}
		got, err := store.GetCode(ctx, c.Code)
		if err != nil {
			t.Fatalf("GetCode with PKCE: %v", err)
		}
		if got.CodeChallenge != challenge {
			t.Errorf("GetCode code_challenge: got %q, want %q", got.CodeChallenge, challenge)
		}
		if got.CodeChallengeMethod != oauth.PKCEMethodS256 {
			t.Errorf("GetCode code_challenge_method: got %q, want %q", got.CodeChallengeMethod, oauth.PKCEMethodS256)
		}
	})

	t.Run("without_pkce", func(t *testing.T) {
		c := &oauth.Code{
			AppID:               appID,
			UserID:              userID,
			RedirectURI:         "https://example.com/callback",
			Scopes:              "openid",
			ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
			CodeChallenge:       "",
			CodeChallengeMethod: "",
		}
		if err := store.CreateCode(ctx, c); err != nil {
			t.Fatalf("CreateCode without PKCE: %v", err)
		}
		got, err := store.GetCode(ctx, c.Code)
		if err != nil {
			t.Fatalf("GetCode without PKCE: %v", err)
		}
		if got.CodeChallenge != "" {
			t.Errorf("GetCode code_challenge: got %q, want empty", got.CodeChallenge)
		}
		if got.CodeChallengeMethod != "" {
			t.Errorf("GetCode code_challenge_method: got %q, want empty", got.CodeChallengeMethod)
		}
	})
}

func TestSQLiteStore_Token(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	appID, userID := seedAppAndUser(t, db)

	t.Run("CreateToken", func(t *testing.T) {
		tok := &oauth.Token{
			AppID:     appID,
			UserID:    userID,
			Scopes:    "openid",
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}
		if err := store.CreateToken(ctx, tok); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		if tok.Token == "" {
			t.Fatal("CreateToken: token not assigned")
		}
		if tok.CreatedAt.IsZero() {
			t.Fatal("CreateToken: created_at not assigned")
		}
	})

	t.Run("GetToken_Found", func(t *testing.T) {
		tok := &oauth.Token{
			AppID:     appID,
			UserID:    userID,
			Scopes:    "openid",
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}
		if err := store.CreateToken(ctx, tok); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		got, err := store.GetToken(ctx, tok.Token)
		if err != nil {
			t.Fatalf("GetToken: %v", err)
		}
		if got.Token != tok.Token {
			t.Errorf("GetToken token: got %q, want %q", got.Token, tok.Token)
		}
		if got.AppID != appID {
			t.Errorf("GetToken app_id: got %q, want %q", got.AppID, appID)
		}
	})

	t.Run("GetToken_NotFound", func(t *testing.T) {
		_, err := store.GetToken(ctx, "nonexistent-token-xyz")
		if !errors.Is(err, oauth.ErrTokenNotFound) {
			t.Errorf("GetToken not found: got %v, want ErrTokenNotFound", err)
		}
	})

	t.Run("DeleteToken", func(t *testing.T) {
		tok := &oauth.Token{
			AppID:     appID,
			UserID:    userID,
			Scopes:    "openid",
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}
		if err := store.CreateToken(ctx, tok); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		if err := store.DeleteToken(ctx, tok.Token); err != nil {
			t.Fatalf("DeleteToken: %v", err)
		}

		_, err := store.GetToken(ctx, tok.Token)
		if !errors.Is(err, oauth.ErrTokenNotFound) {
			t.Errorf("GetToken after DeleteToken: got %v, want ErrTokenNotFound", err)
		}
	})
}

func TestSQLiteStore_RefreshToken(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	appID, userID := seedAppAndUser(t, db)

	t.Run("CreateRefreshToken", func(t *testing.T) {
		rt := &oauth.RefreshToken{
			AppID:     appID,
			UserID:    userID,
			Scopes:    "openid",
			ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
		}
		if err := store.CreateRefreshToken(ctx, rt); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		if rt.Token == "" {
			t.Fatal("CreateRefreshToken: token not assigned")
		}
	})

	t.Run("GetRefreshToken_Found", func(t *testing.T) {
		rt := &oauth.RefreshToken{
			AppID:     appID,
			UserID:    userID,
			Scopes:    "openid",
			ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
		}
		if err := store.CreateRefreshToken(ctx, rt); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}

		got, err := store.GetRefreshToken(ctx, rt.Token)
		if err != nil {
			t.Fatalf("GetRefreshToken: %v", err)
		}
		if got.Token != rt.Token {
			t.Errorf("GetRefreshToken token: got %q, want %q", got.Token, rt.Token)
		}
		if got.UsedAt != nil {
			t.Errorf("GetRefreshToken used_at: expected nil, got %v", got.UsedAt)
		}
	})

	t.Run("GetRefreshToken_NotFound", func(t *testing.T) {
		_, err := store.GetRefreshToken(ctx, "nonexistent-refresh-xyz")
		if !errors.Is(err, oauth.ErrRefreshNotFound) {
			t.Errorf("GetRefreshToken not found: got %v, want ErrRefreshNotFound", err)
		}
	})

	t.Run("MarkRefreshTokenUsed", func(t *testing.T) {
		rt := &oauth.RefreshToken{
			AppID:     appID,
			UserID:    userID,
			Scopes:    "openid",
			ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
		}
		if err := store.CreateRefreshToken(ctx, rt); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}

		if err := store.MarkRefreshTokenUsed(ctx, rt.Token); err != nil {
			t.Fatalf("MarkRefreshTokenUsed: %v", err)
		}

		got, err := store.GetRefreshToken(ctx, rt.Token)
		if err != nil {
			t.Fatalf("GetRefreshToken after MarkRefreshTokenUsed: %v", err)
		}
		if got.UsedAt == nil {
			t.Error("GetRefreshToken after MarkRefreshTokenUsed: expected UsedAt to be set")
		}
	})
}

func TestSQLiteStore_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	appID, userID := seedAppAndUser(t, db)

	// Create an expired code.
	expiredCode := &oauth.Code{
		AppID:       appID,
		UserID:      userID,
		RedirectURI: "https://example.com/cb",
		Scopes:      "openid",
		ExpiresAt:   time.Now().UTC().Add(-1 * time.Hour), // expired
	}
	if err := store.CreateCode(ctx, expiredCode); err != nil {
		t.Fatalf("CreateCode expired: %v", err)
	}

	// Create a valid code.
	validCode := &oauth.Code{
		AppID:       appID,
		UserID:      userID,
		RedirectURI: "https://example.com/cb",
		Scopes:      "openid",
		ExpiresAt:   time.Now().UTC().Add(1 * time.Hour),
	}
	if err := store.CreateCode(ctx, validCode); err != nil {
		t.Fatalf("CreateCode valid: %v", err)
	}

	// Create an expired token.
	expiredToken := &oauth.Token{
		AppID:     appID,
		UserID:    userID,
		Scopes:    "openid",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	if err := store.CreateToken(ctx, expiredToken); err != nil {
		t.Fatalf("CreateToken expired: %v", err)
	}

	// Create a valid token.
	validToken := &oauth.Token{
		AppID:     appID,
		UserID:    userID,
		Scopes:    "openid",
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
	}
	if err := store.CreateToken(ctx, validToken); err != nil {
		t.Fatalf("CreateToken valid: %v", err)
	}

	// Create an expired refresh token.
	expiredRT := &oauth.RefreshToken{
		AppID:     appID,
		UserID:    userID,
		Scopes:    "openid",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	if err := store.CreateRefreshToken(ctx, expiredRT); err != nil {
		t.Fatalf("CreateRefreshToken expired: %v", err)
	}

	// Create a valid refresh token.
	validRT := &oauth.RefreshToken{
		AppID:     appID,
		UserID:    userID,
		Scopes:    "openid",
		ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := store.CreateRefreshToken(ctx, validRT); err != nil {
		t.Fatalf("CreateRefreshToken valid: %v", err)
	}

	// Run cleanup.
	if err := store.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	// Expired records should be gone.
	if _, err := store.GetCode(ctx, expiredCode.Code); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Errorf("expired code: expected ErrCodeNotFound, got %v", err)
	}
	if _, err := store.GetToken(ctx, expiredToken.Token); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Errorf("expired token: expected ErrTokenNotFound, got %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, expiredRT.Token); !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Errorf("expired refresh token: expected ErrRefreshNotFound, got %v", err)
	}

	// Valid records should survive.
	if _, err := store.GetCode(ctx, validCode.Code); err != nil {
		t.Errorf("valid code should survive DeleteExpired: %v", err)
	}
	if _, err := store.GetToken(ctx, validToken.Token); err != nil {
		t.Errorf("valid token should survive DeleteExpired: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, validRT.Token); err != nil {
		t.Errorf("valid refresh token should survive DeleteExpired: %v", err)
	}
}

func TestSQLiteStore_EnsureSigningKeys_GeneratesWhenEmpty(t *testing.T) {
	ctx := context.Background()
	database := testutil.NewTestDB(t)
	store := oauth.NewStore(database)

	if err := store.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys: %v", err)
	}

	keys, err := store.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("signing keys = %d, want 1", len(keys))
	}
	key := keys[0]
	if key.KID == "" {
		t.Fatal("generated key has an empty kid")
	}
	if key.Retired() {
		t.Error("generated key is retired")
	}
	if key.PublicKey() == nil || key.PublicKey().N.BitLen() != 2048 {
		t.Errorf("generated key modulus = %v bits, want 2048", key.PublicKey().N.BitLen())
	}

	// A second call is a no-op: still exactly one key, same kid.
	if err := store.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys second call: %v", err)
	}
	again, err := store.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys second call: %v", err)
	}
	if len(again) != 1 || again[0].KID != key.KID {
		t.Fatalf("second EnsureSigningKeys changed the ring: got %d keys", len(again))
	}

	// Generation must not touch oidc_config: new keys live only in the table.
	var legacy int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oidc_config WHERE key = 'rsa_private_key'`).Scan(&legacy); err != nil {
		t.Fatalf("count legacy key: %v", err)
	}
	if legacy != 0 {
		t.Errorf("oidc_config legacy rows = %d, want 0", legacy)
	}
}

// TestSQLiteStore_EnsureSigningKeys_ImportsLegacyKey proves the upgrade path:
// the single key in oidc_config is imported once with its derived kid, the
// legacy row is left untouched for a rollback, and a second start is a no-op.
func TestSQLiteStore_EnsureSigningKeys_ImportsLegacyKey(t *testing.T) {
	ctx := context.Background()
	database := testutil.NewTestDB(t)
	store := oauth.NewStore(database)

	legacyPEM, wantKID := newLegacySigningKey(t)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO oidc_config (key, value, created_at, updated_at) VALUES ('rsa_private_key', ?, ?, ?)`,
		string(legacyPEM), time.Now().UTC().Add(-48*time.Hour), time.Now().UTC(),
	); err != nil {
		t.Fatalf("insert legacy key: %v", err)
	}

	if err := store.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys: %v", err)
	}

	keys, err := store.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("signing keys after import = %d, want 1", len(keys))
	}
	if keys[0].KID != wantKID {
		t.Errorf("imported kid = %q, want derived %q", keys[0].KID, wantKID)
	}
	if keys[0].PublicKey().N.Cmp(legacyPublicKey(t, legacyPEM).N) != 0 {
		t.Error("imported key is not the legacy key")
	}

	// The legacy row is the rollback path; it must still be there, unchanged.
	var stored string
	if err := database.QueryRowContext(ctx,
		`SELECT value FROM oidc_config WHERE key = 'rsa_private_key'`).Scan(&stored); err != nil {
		t.Fatalf("read legacy key after import: %v", err)
	}
	if stored != string(legacyPEM) {
		t.Error("legacy oidc_config row was modified by the import")
	}

	// Idempotent on a second start.
	if err := store.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys second call: %v", err)
	}
	again, err := store.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys second call: %v", err)
	}
	if len(again) != 1 || again[0].KID != wantKID {
		t.Fatalf("second start changed the ring: got %d keys", len(again))
	}
}

// TestSQLiteStore_EnsureSigningKeys_AllRetiredRecovers proves startup still
// produces a usable keyring when every stored key was retired by direct SQL
// (the API refuses to retire the last one).
func TestSQLiteStore_EnsureSigningKeys_AllRetiredRecovers(t *testing.T) {
	ctx := context.Background()
	database := testutil.NewTestDB(t)
	store := oauth.NewStore(database)

	if err := store.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE oauth_signing_keys SET retired_at = ?`, time.Now().UTC()); err != nil {
		t.Fatalf("retire all keys: %v", err)
	}

	if err := store.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys after all keys were retired: %v", err)
	}
	keys, err := store.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys after recovery = %d, want 2 (retired history + a new key)", len(keys))
	}
	if keys[0].Retired() {
		t.Error("the newest key is retired; the issuer still cannot sign")
	}
}

// TestSQLiteStore_EnsureSigningKeys_Persistence verifies the imported key
// survives a real restart (a new db.Open on the same file) and is imported
// only once.
func TestSQLiteStore_EnsureSigningKeys_Persistence(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	db1, err := db.Open(ctx, dbPath, slog.Default())
	if err != nil {
		t.Fatalf("db.Open (first): %v", err)
	}
	store1 := oauth.NewStore(db1)
	if err := store1.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys (first): %v", err)
	}
	first, err := store1.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys (first): %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("signing keys (first) = %d, want 1", len(first))
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("db1.Close: %v", err)
	}

	db2, err := db.Open(ctx, dbPath, slog.Default())
	if err != nil {
		t.Fatalf("db.Open (second): %v", err)
	}
	defer db2.Close()
	store2 := oauth.NewStore(db2)
	if err := store2.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("EnsureSigningKeys (second): %v", err)
	}
	second, err := store2.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys (second): %v", err)
	}
	if len(second) != 1 || second[0].KID != first[0].KID {
		t.Fatalf("key changed across a restart: %d keys, first kid %q", len(second), first[0].KID)
	}
}

// newLegacySigningKey returns a PKCS#1 PEM and the kid derived from it the way
// Passage has always derived it (base64url SHA-256 of the PKIX public key DER).
func newLegacySigningKey(t *testing.T) ([]byte, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate legacy key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return pemBytes, derivedKID(t, &privateKey.PublicKey)
}

// derivedKID computes the kid exactly as the production derivation does.
func derivedKID(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	sum := sha256.Sum256(pubDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// legacyPublicKey parses a legacy PEM into its public key for comparison.
func legacyPublicKey(t *testing.T, pemBytes []byte) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("legacy PEM decode failed")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse legacy key: %v", err)
	}
	return &privateKey.PublicKey
}
