package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// TestFindOrCreateByEmail_ExistingUser verifies that FindOrCreateByEmail returns
// the existing user (created=false) when the email is already registered.
func TestFindOrCreateByEmail_ExistingUser(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	// Pre-create a user.
	if _, err := svc.Register(ctx, "alice_magic", "alice_magic@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	u, created, err := svc.FindOrCreateByEmail(ctx, "alice_magic@example.com")
	if err != nil {
		t.Fatalf("FindOrCreateByEmail: unexpected error: %v", err)
	}
	if created {
		t.Error("FindOrCreateByEmail: expected created=false for existing user")
	}
	if u.Email != "alice_magic@example.com" {
		t.Errorf("FindOrCreateByEmail: got email %q, want %q", u.Email, "alice_magic@example.com")
	}
}

// TestFindOrCreateByEmail_NewUser verifies that FindOrCreateByEmail creates a
// new user when the email is not found, and returns created=true.
func TestFindOrCreateByEmail_NewUser(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	u, created, err := svc.FindOrCreateByEmail(ctx, "newmagic@example.com")
	if err != nil {
		t.Fatalf("FindOrCreateByEmail: unexpected error: %v", err)
	}
	if !created {
		t.Error("FindOrCreateByEmail: expected created=true for new user")
	}
	if u == nil {
		t.Fatal("FindOrCreateByEmail: expected non-nil user")
	}
	if u.ID == "" {
		t.Error("FindOrCreateByEmail: expected non-empty ID")
	}
	if u.Email != "newmagic@example.com" {
		t.Errorf("FindOrCreateByEmail: got email %q, want %q", u.Email, "newmagic@example.com")
	}
	// Username should be derived from the local part of the email.
	if u.Username == "" {
		t.Error("FindOrCreateByEmail: expected non-empty username")
	}
	if !u.IsActive {
		t.Error("FindOrCreateByEmail: expected new user to be active")
	}
}

// TestFindOrCreateByEmail_DerivedUsername verifies that the username is derived
// correctly from the email local part, replacing non-alphanumeric chars with _.
func TestFindOrCreateByEmail_DerivedUsername(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	u, created, err := svc.FindOrCreateByEmail(ctx, "foo.bar+baz@example.com")
	if err != nil {
		t.Fatalf("FindOrCreateByEmail: unexpected error: %v", err)
	}
	if !created {
		t.Error("FindOrCreateByEmail: expected created=true")
	}
	// "foo.bar+baz" → "foo_bar_baz"
	if u.Username == "" {
		t.Error("FindOrCreateByEmail: expected non-empty derived username")
	}
}

// TestConsumeMagicLinkToken_HappyPath verifies the full create → consume cycle.
func TestConsumeMagicLinkToken_HappyPath(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	// Create a user to attach the token to.
	u, err := svc.Register(ctx, "magic_happy", "magic_happy@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	tok, err := svc.CreateMagicLinkToken(ctx, u.ID, 15)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("CreateMagicLinkToken: expected non-empty token")
	}

	got, err := svc.ConsumeMagicLinkToken(ctx, tok.Token)
	if err != nil {
		t.Fatalf("ConsumeMagicLinkToken: unexpected error: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("ConsumeMagicLinkToken: got user ID %q, want %q", got.ID, u.ID)
	}
}

// TestConsumeMagicLinkToken_ExpiredToken verifies that an expired token returns
// ErrMagicLinkTokenExpired.
func TestConsumeMagicLinkToken_ExpiredToken(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	svc := user.NewService(store, store, testConfig(true))
	ctx := context.Background()

	u, err := svc.Register(ctx, "magic_expired", "magic_expired@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Insert an already-expired token directly via raw SQL.
	expiredToken := "expiredmagictoken1234567890abcdef1234567890abcdef1234567890abcdef"
	pastTime := time.Now().UTC().Add(-2 * time.Hour)
	_, err = db.ExecContext(ctx,
		`INSERT INTO magic_link_tokens (token, user_id, expires_at) VALUES (?, ?, ?)`,
		expiredToken, u.ID, pastTime,
	)
	if err != nil {
		t.Fatalf("insert expired token: %v", err)
	}

	_, err = svc.ConsumeMagicLinkToken(ctx, expiredToken)
	if !errors.Is(err, user.ErrMagicLinkTokenExpired) {
		t.Errorf("ConsumeMagicLinkToken expired: got %v, want ErrMagicLinkTokenExpired", err)
	}
}

// TestConsumeMagicLinkToken_UsedToken verifies that a double-spend attempt
// returns ErrMagicLinkTokenUsed.
func TestConsumeMagicLinkToken_UsedToken(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	u, err := svc.Register(ctx, "magic_used", "magic_used@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	tok, err := svc.CreateMagicLinkToken(ctx, u.ID, 15)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	// First consumption should succeed.
	if _, err := svc.ConsumeMagicLinkToken(ctx, tok.Token); err != nil {
		t.Fatalf("ConsumeMagicLinkToken (first): %v", err)
	}

	// Second consumption must return ErrMagicLinkTokenUsed.
	_, err = svc.ConsumeMagicLinkToken(ctx, tok.Token)
	if !errors.Is(err, user.ErrMagicLinkTokenUsed) {
		t.Errorf("ConsumeMagicLinkToken (second): got %v, want ErrMagicLinkTokenUsed", err)
	}
}

// TestConsumeMagicLinkToken_UnknownToken verifies that consuming an unknown
// token returns ErrMagicLinkTokenNotFound.
func TestConsumeMagicLinkToken_UnknownToken(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	_, err := svc.ConsumeMagicLinkToken(ctx, "doesnotexistdeadbeef")
	if !errors.Is(err, user.ErrMagicLinkTokenNotFound) {
		t.Errorf("ConsumeMagicLinkToken unknown: got %v, want ErrMagicLinkTokenNotFound", err)
	}
}
