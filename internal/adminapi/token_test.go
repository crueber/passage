package adminapi_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/adminapi"
	"github.com/crueber/passage/internal/testutil"
)

func TestGenerateToken(t *testing.T) {
	t.Parallel()

	t.Run("shape and prefix", func(t *testing.T) {
		t.Parallel()
		plaintext, hash, err := adminapi.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if !strings.HasPrefix(plaintext, adminapi.TokenPrefix) {
			t.Errorf("token %q does not start with %q", plaintext, adminapi.TokenPrefix)
		}
		// 32 random bytes in unpadded base64url is 43 characters.
		if got, want := len(plaintext), len(adminapi.TokenPrefix)+43; got != want {
			t.Errorf("token length = %d, want %d", got, want)
		}
		if got, want := len(hash), 64; got != want {
			t.Errorf("hash length = %d, want %d hex characters", got, want)
		}
		if hash != adminapi.HashToken(plaintext) {
			t.Error("returned hash does not match HashToken(plaintext)")
		}
		if strings.Contains(hash, plaintext) || hash == plaintext {
			t.Error("token hash contains the plaintext")
		}
	})

	t.Run("tokens are unique", func(t *testing.T) {
		t.Parallel()
		seen := make(map[string]bool)
		for i := 0; i < 64; i++ {
			plaintext, hash, err := adminapi.GenerateToken()
			if err != nil {
				t.Fatalf("GenerateToken: %v", err)
			}
			if seen[plaintext] || seen[hash] {
				t.Fatalf("generated a duplicate token on iteration %d", i)
			}
			seen[plaintext] = true
			seen[hash] = true
		}
	})
}

func TestHashToken(t *testing.T) {
	t.Parallel()

	if got, want := adminapi.HashToken("pst_test"), adminapi.HashToken("pst_test"); got != want {
		t.Errorf("HashToken is not deterministic: %q != %q", got, want)
	}
	if adminapi.HashToken("pst_a") == adminapi.HashToken("pst_b") {
		t.Error("different tokens hash to the same value")
	}
	hash := adminapi.HashToken("pst_test")
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
	for _, c := range hash {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("hash contains a non-lowercase-hex character %q", c)
		}
	}
}

func TestToken_Revoked(t *testing.T) {
	t.Parallel()

	var token adminapi.Token
	if token.Revoked() {
		t.Error("zero-value token reports revoked")
	}
	token.RevokedAt = time.Now().UTC()
	if !token.Revoked() {
		t.Error("token with revoked_at set reports active")
	}
}

// TestService_Lifecycle covers create, list, authenticate, and revoke against a
// real in-memory database.
func TestService_Lifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := testutil.NewTestDB(t)
	store := adminapi.NewStore(database)
	svc := adminapi.NewService(store, slog.Default())

	plaintext, created, err := svc.Create(ctx, "  grafana exporter  ")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Name != "grafana exporter" {
		t.Errorf("name = %q, want trimmed %q", created.Name, "grafana exporter")
	}
	if created.ID == "" {
		t.Error("created token has no ID")
	}
	if created.CreatedAt.IsZero() {
		t.Error("created token has no created_at")
	}
	if !strings.HasPrefix(plaintext, adminapi.TokenPrefix) {
		t.Errorf("plaintext %q lacks the token prefix", plaintext)
	}

	stored, err := store.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.TokenHash != adminapi.HashToken(plaintext) {
		t.Error("stored hash is not the hash of the plaintext")
	}
	if stored.TokenHash == plaintext {
		t.Fatal("plaintext token was stored")
	}
	if !stored.LastUsedAt.IsZero() {
		t.Error("a fresh token already has last_used_at set")
	}

	listed, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("List = %+v, want the one created token", listed)
	}

	// A successful authentication updates last_used_at.
	authed, err := svc.Authenticate(ctx, plaintext)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if authed.ID != created.ID {
		t.Errorf("authenticated token ID = %q, want %q", authed.ID, created.ID)
	}
	if authed.LastUsedAt.IsZero() {
		t.Error("successful authentication did not set last_used_at on the returned token")
	}
	persisted, err := store.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID after authenticate: %v", err)
	}
	if persisted.LastUsedAt.IsZero() {
		t.Error("last_used_at was not persisted")
	}

	// Revocation invalidates the token but keeps the row.
	revoked, err := svc.Revoke(ctx, created.ID)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !revoked.Revoked() {
		t.Error("Revoke returned a token that is not marked revoked")
	}
	if _, err := svc.Authenticate(ctx, plaintext); !errors.Is(err, adminapi.ErrTokenNotFound) {
		t.Errorf("Authenticate after revoke error = %v, want ErrTokenNotFound", err)
	}

	// Revoking twice is idempotent (the admin UI may double-submit).
	again, err := svc.Revoke(ctx, created.ID)
	if err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	if !again.RevokedAt.Equal(revoked.RevokedAt) {
		t.Error("second Revoke changed revoked_at")
	}

	// The row is still listed so the history stays visible.
	listed, err = svc.List(ctx)
	if err != nil {
		t.Fatalf("List after revoke: %v", err)
	}
	if len(listed) != 1 || !listed[0].Revoked() {
		t.Fatalf("List after revoke = %+v, want the revoked token", listed)
	}
}

func TestService_CreateRequiresName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := adminapi.NewService(adminapi.NewStore(testutil.NewTestDB(t)), slog.Default())

	for _, name := range []string{"", "   ", "\t\n"} {
		if _, _, err := svc.Create(ctx, name); !errors.Is(err, adminapi.ErrNameRequired) {
			t.Errorf("Create(%q) error = %v, want ErrNameRequired", name, err)
		}
	}
}

func TestService_RevokeUnknownToken(t *testing.T) {
	t.Parallel()
	svc := adminapi.NewService(adminapi.NewStore(testutil.NewTestDB(t)), slog.Default())

	if _, err := svc.Revoke(context.Background(), "does-not-exist"); !errors.Is(err, adminapi.ErrTokenNotFound) {
		t.Errorf("Revoke(unknown) error = %v, want ErrTokenNotFound", err)
	}
}

// TestService_AuthenticateRejectsBadCredentials is table-driven over every way
// a bearer credential can be wrong.
func TestService_AuthenticateRejectsBadCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := testutil.NewTestDB(t)
	store := adminapi.NewStore(database)
	svc := adminapi.NewService(store, slog.Default())

	valid, _, err := svc.Create(ctx, "valid")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	revokedPlain, revokedToken, err := svc.Create(ctx, "revoked")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Revoke(ctx, revokedToken.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no prefix", strings.TrimPrefix(valid, adminapi.TokenPrefix)},
		{"wrong prefix", "pst2_" + strings.TrimPrefix(valid, adminapi.TokenPrefix)},
		{"unknown token", adminapi.TokenPrefix + strings.Repeat("A", 43)},
		{"truncated known token", valid[:len(valid)-1]},
		{"revoked token", revokedPlain},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := svc.Authenticate(ctx, tc.token); !errors.Is(err, adminapi.ErrTokenNotFound) {
				t.Errorf("Authenticate(%q) error = %v, want ErrTokenNotFound", tc.token, err)
			}
		})
	}
}
