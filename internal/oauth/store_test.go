package oauth_test

import (
	"context"
	"crypto/x509"
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

func TestSQLiteStore_GetOrCreateRSAKey(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	// First call: creates and stores the key.
	pem1, kid1, err := store.GetOrCreateRSAKey(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateRSAKey first call: %v", err)
	}
	if len(pem1) == 0 {
		t.Fatal("GetOrCreateRSAKey: returned empty PEM")
	}
	if kid1 == "" {
		t.Fatal("GetOrCreateRSAKey: returned empty kid")
	}

	// Second call: returns the same key (idempotent).
	pem2, kid2, err := store.GetOrCreateRSAKey(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateRSAKey second call: %v", err)
	}
	if string(pem1) != string(pem2) {
		t.Error("GetOrCreateRSAKey: second call returned different PEM than first")
	}
	if kid1 != kid2 {
		t.Error("GetOrCreateRSAKey: second call returned different kid than first")
	}

	// The PEM should be parseable as an RSA private key.
	block, _ := pem.Decode(pem1)
	if block == nil {
		t.Fatal("GetOrCreateRSAKey: PEM decode returned nil block")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Errorf("GetOrCreateRSAKey: PEM is not a valid RSA private key: %v", err)
	}
}

// TestSQLiteStore_GetOrCreateRSAKey_Persistence verifies that the RSA key
// survives a simulated service restart (new db.Open on the same file).
func TestSQLiteStore_GetOrCreateRSAKey_Persistence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Open the database for the first time and generate the RSA key.
	db1, err := db.Open(ctx, dbPath, slog.Default())
	if err != nil {
		t.Fatalf("db.Open (first): %v", err)
	}
	store1 := oauth.NewStore(db1)
	pem1, kid1, err := store1.GetOrCreateRSAKey(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateRSAKey (first): %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("db1.Close: %v", err)
	}

	// Re-open the same file — simulates a process restart.
	db2, err := db.Open(ctx, dbPath, slog.Default())
	if err != nil {
		t.Fatalf("db.Open (second): %v", err)
	}
	store2 := oauth.NewStore(db2)
	pem2, kid2, err := store2.GetOrCreateRSAKey(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateRSAKey (second): %v", err)
	}
	if err := db2.Close(); err != nil {
		t.Fatalf("db2.Close: %v", err)
	}

	// The key must be identical across restarts.
	if string(pem1) != string(pem2) {
		t.Error("GetOrCreateRSAKey persistence: PEM differs after re-open")
	}
	if kid1 != kid2 {
		t.Errorf("GetOrCreateRSAKey persistence: kid differs: first=%q, second=%q", kid1, kid2)
	}
}
