package user_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// TestResetPassword_PasswordTooLongDoesNotBurnToken verifies that a password
// exceeding bcrypt's 72-byte limit fails before the reset token is claimed, so
// the user can retry with a shorter password using the same link.
func TestResetPassword_PasswordTooLongDoesNotBurnToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	cfg := &config.Config{
		Auth: config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
	}
	svc := user.NewService(store, store, nil, cfg)

	if _, err := svc.Register(ctx, "resetlong", "resetlong@example.com", "oldpassword123"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	token, err := svc.GeneratePasswordReset(ctx, "resetlong@example.com")
	if err != nil || token == "" {
		t.Fatalf("GeneratePasswordReset: token=%q err=%v", token, err)
	}

	// 73-byte password must fail with bcrypt.ErrPasswordTooLong without burning the token.
	tooLong := strings.Repeat("a", 73)
	if err := svc.ResetPassword(ctx, token, tooLong); !errors.Is(err, bcrypt.ErrPasswordTooLong) {
		t.Fatalf("ResetPassword(73 bytes) error = %v, want bcrypt.ErrPasswordTooLong", err)
	}

	// Same token must still work with a valid password.
	if err := svc.ResetPassword(ctx, token, "newvalidpassword"); err != nil {
		t.Fatalf("ResetPassword(valid retry) failed after too-long attempt: %v", err)
	}

	// And the new password must authenticate.
	if _, err := svc.Authenticate(ctx, "resetlong", "newvalidpassword"); err != nil {
		t.Errorf("Authenticate with new password failed: %v", err)
	}
}
