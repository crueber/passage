package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// testConfig returns a minimal Config suitable for unit tests.
// BcryptCost 10 is the minimum allowed and keeps tests fast.
func testConfig(allowRegistration bool) *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			AllowRegistration: allowRegistration,
			BcryptCost:        10,
		},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
	}
}

func newUserService(t *testing.T, allowRegistration bool) *user.Service {
	t.Helper()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	return user.NewService(store, store, testConfig(allowRegistration))
}

// TestRegister verifies that a new user can be created with valid inputs and
// that the returned user has the expected fields set.
func TestRegister(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	u, err := svc.Register(ctx, "alice", "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}
	if u.ID == "" {
		t.Error("Register: expected non-empty ID")
	}
	if u.Username != "alice" {
		t.Errorf("Register: got username %q, want %q", u.Username, "alice")
	}
	if u.Email != "alice@example.com" {
		t.Errorf("Register: got email %q, want %q", u.Email, "alice@example.com")
	}
	if !u.IsActive {
		t.Error("Register: expected user to be active")
	}
	if u.PasswordHash == "" {
		t.Error("Register: expected non-empty PasswordHash")
	}
	if u.PasswordHash == "password123" {
		t.Error("Register: PasswordHash must not be the plaintext password")
	}
}

// TestRegister_DisabledRegistration verifies that registration returns
// ErrRegistrationDisabled when the config flag is off.
func TestRegister_DisabledRegistration(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, false)
	ctx := context.Background()

	_, err := svc.Register(ctx, "bob", "bob@example.com", "password123")
	if !errors.Is(err, user.ErrRegistrationDisabled) {
		t.Errorf("Register with disabled registration: got %v, want ErrRegistrationDisabled", err)
	}
}

// TestRegister_DuplicateUsername verifies that registering a duplicate username
// returns ErrUsernameTaken.
func TestRegister_DuplicateUsername(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "charlie", "charlie@example.com", "password123"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	_, err := svc.Register(ctx, "charlie", "charlie2@example.com", "password123")
	if !errors.Is(err, user.ErrUsernameTaken) {
		t.Errorf("duplicate username: got %v, want ErrUsernameTaken", err)
	}
}

// TestRegister_DuplicateEmail verifies that registering a duplicate email
// returns ErrEmailTaken.
func TestRegister_DuplicateEmail(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "dave", "shared@example.com", "password123"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	_, err := svc.Register(ctx, "dave2", "shared@example.com", "password123")
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Errorf("duplicate email: got %v, want ErrEmailTaken", err)
	}
}

// TestAuthenticate verifies that a registered user can authenticate with the
// correct password and that the returned user matches.
func TestAuthenticate(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "eve", "eve@example.com", "s3cr3tP@ss"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	u, err := svc.Authenticate(ctx, "eve", "s3cr3tP@ss")
	if err != nil {
		t.Fatalf("Authenticate: unexpected error: %v", err)
	}
	if u.Username != "eve" {
		t.Errorf("Authenticate: got username %q, want %q", u.Username, "eve")
	}
}

// TestAuthenticate_WrongPassword verifies that a wrong password returns
// ErrInvalidCredentials.
func TestAuthenticate_WrongPassword(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "frank", "frank@example.com", "correcthorse"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err := svc.Authenticate(ctx, "frank", "wrongpassword")
	if !errors.Is(err, user.ErrInvalidCredentials) {
		t.Errorf("wrong password: got %v, want ErrInvalidCredentials", err)
	}
}

// TestAuthenticate_UnknownUser verifies that authenticating with a username
// that does not exist returns ErrInvalidCredentials (not ErrNotFound, which
// would leak user enumeration information).
func TestAuthenticate_UnknownUser(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	_, err := svc.Authenticate(ctx, "nobody", "password123")
	if !errors.Is(err, user.ErrInvalidCredentials) {
		t.Errorf("unknown user: got %v, want ErrInvalidCredentials", err)
	}
}

// TestAuthenticate_InactiveUser verifies that an inactive user cannot
// authenticate, even with the correct password.
func TestAuthenticate_InactiveUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	svc := user.NewService(store, store, testConfig(true))
	ctx := context.Background()

	u, err := svc.Register(ctx, "grace", "grace@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Deactivate the user directly via the store.
	u.IsActive = false
	if err := store.Update(ctx, u); err != nil {
		t.Fatalf("Update (deactivate): %v", err)
	}

	_, err = svc.Authenticate(ctx, "grace", "password123")
	if !errors.Is(err, user.ErrUserInactive) {
		t.Errorf("inactive user: got %v, want ErrUserInactive", err)
	}
}

// TestGeneratePasswordReset_UnknownEmail verifies that GeneratePasswordReset
// returns an empty token and no error when the email is not found, to avoid
// email enumeration.
func TestGeneratePasswordReset_UnknownEmail(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	token, err := svc.GeneratePasswordReset(ctx, "nobody@example.com")
	if err != nil {
		t.Errorf("unknown email: unexpected error: %v", err)
	}
	if token != "" {
		t.Errorf("unknown email: expected empty token, got %q", token)
	}
}

// TestPasswordReset_HappyPath verifies the full reset cycle: generate a token,
// then use it to change the password, then authenticate with the new password.
func TestPasswordReset_HappyPath(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "heidi", "heidi@example.com", "oldpassword"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	token, err := svc.GeneratePasswordReset(ctx, "heidi@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordReset: %v", err)
	}
	if token == "" {
		t.Fatal("GeneratePasswordReset: expected a non-empty token")
	}

	if err := svc.ResetPassword(ctx, token, "newpassword!"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Old password must no longer work.
	if _, err := svc.Authenticate(ctx, "heidi", "oldpassword"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Errorf("old password after reset: got %v, want ErrInvalidCredentials", err)
	}

	// New password must work.
	if _, err := svc.Authenticate(ctx, "heidi", "newpassword!"); err != nil {
		t.Errorf("new password after reset: unexpected error: %v", err)
	}
}

// TestPasswordReset_TokenUsed verifies that using the same reset token twice
// returns ErrTokenUsed on the second attempt.
func TestPasswordReset_TokenUsed(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "ivan", "ivan@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	token, err := svc.GeneratePasswordReset(ctx, "ivan@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordReset: %v", err)
	}

	if err := svc.ResetPassword(ctx, token, "newpassword1"); err != nil {
		t.Fatalf("first ResetPassword: %v", err)
	}

	err = svc.ResetPassword(ctx, token, "newpassword2")
	if !errors.Is(err, user.ErrTokenUsed) {
		t.Errorf("second reset with same token: got %v, want ErrTokenUsed", err)
	}
}

// TestPasswordReset_TokenExpired verifies that an expired token returns
// ErrTokenExpired.
func TestPasswordReset_TokenExpired(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	svc := user.NewService(store, store, testConfig(true))
	ctx := context.Background()

	if _, err := svc.Register(ctx, "judy", "judy@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Look up the user to get their ID, then insert an already-expired token directly.
	u, err := store.GetByUsername(ctx, "judy")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}

	// Directly insert an expired token using the raw store.
	// CreateResetToken always sets expiry to +1 hour, so we insert via SQL instead.
	expiredToken := "expiredtokenvalue1234567890abcdef"
	expiredAt := time.Now().UTC().Add(-2 * time.Hour)
	_, err = db.ExecContext(ctx,
		`INSERT INTO password_reset_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		expiredToken, u.ID, expiredAt, time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert expired token: %v", err)
	}

	err = svc.ResetPassword(ctx, expiredToken, "newpassword!")
	if !errors.Is(err, user.ErrTokenExpired) {
		t.Errorf("expired token: got %v, want ErrTokenExpired", err)
	}
}
