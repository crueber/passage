package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/config"
)

// Service implements business logic for user management.
type Service struct {
	store      Store
	tokenStore TokenStore
	cfg        *config.Config
}

// NewService creates a new Service with the given dependencies.
func NewService(store Store, tokenStore TokenStore, cfg *config.Config) *Service {
	return &Service{
		store:      store,
		tokenStore: tokenStore,
		cfg:        cfg,
	}
}

// Register creates a new user account. It checks that registration is enabled,
// validates inputs, hashes the password with bcrypt, and persists the user.
func (s *Service) Register(ctx context.Context, username, email, password string) (*User, error) {
	if !s.cfg.Auth.AllowRegistration {
		return nil, ErrRegistrationDisabled
	}

	if username == "" {
		return nil, ErrUsernameRequired
	}
	if email == "" {
		return nil, ErrEmailRequired
	}
	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.Auth.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("register hash password: %w", err)
	}

	u := &User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		IsActive:     true,
		IsAdmin:      false,
		Roles:        "[]",
	}

	if err := s.store.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("register create user: %w", err)
	}
	return u, nil
}

// CreateAdmin creates a new admin user account, bypassing the allow_registration
// setting. It is used only during the initial /setup flow to create the first
// admin when no admin yet exists.
func (s *Service) CreateAdmin(ctx context.Context, username, email, password string) (*User, error) {
	if username == "" {
		return nil, ErrUsernameRequired
	}
	if email == "" {
		return nil, ErrEmailRequired
	}
	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.Auth.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("create admin hash password: %w", err)
	}

	u := &User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		IsActive:     true,
		IsAdmin:      true,
		Roles:        "[]",
	}

	if err := s.store.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("create admin create user: %w", err)
	}
	return u, nil
}

// Authenticate verifies credentials and returns the user if valid.
// Returns ErrInvalidCredentials if the username does not exist or the password
// is wrong. Returns ErrUserInactive if the account has been disabled.
func (s *Service) Authenticate(ctx context.Context, username, password string) (*User, error) {
	u, err := s.store.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Hash a dummy value to maintain constant-time behavior and
			// prevent user enumeration via timing side-channels.
			_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummyhashfortimingnnn.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), []byte(password))
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if !u.IsActive {
		return nil, ErrUserInactive
	}

	return u, nil
}

// GeneratePasswordReset looks up the user by email and creates a reset token.
// If the email is not found, nil is returned for both values to avoid email
// enumeration.
func (s *Service) GeneratePasswordReset(ctx context.Context, email string) (token string, err error) {
	u, err := s.store.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Do not reveal whether the email exists.
			return "", nil
		}
		return "", fmt.Errorf("generate password reset: %w", err)
	}

	token, err = s.tokenStore.CreateResetToken(ctx, u.ID)
	if err != nil {
		return "", fmt.Errorf("generate password reset create token: %w", err)
	}
	return token, nil
}

// ResetPassword validates the token and sets the user's password to newPassword.
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	rt, err := s.tokenStore.GetResetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("reset password get token: %w", err)
	}

	if rt.UsedAt != nil {
		return ErrTokenUsed
	}

	if rt.ExpiresAt.Before(time.Now().UTC()) {
		return ErrTokenExpired
	}

	if err := s.ChangePassword(ctx, rt.UserID, newPassword); err != nil {
		return fmt.Errorf("reset password change: %w", err)
	}

	if err := s.tokenStore.MarkResetTokenUsed(ctx, token); err != nil {
		return fmt.Errorf("reset password mark token used: %w", err)
	}
	return nil
}

// ChangePassword sets a new bcrypt-hashed password for the given user.
func (s *Service) ChangePassword(ctx context.Context, userID, newPassword string) error {
	if len(newPassword) < 8 {
		return ErrPasswordTooShort
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("change password hash: %w", err)
	}

	u, err := s.store.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("change password get user: %w", err)
	}

	u.PasswordHash = string(hash)
	if err := s.store.Update(ctx, u); err != nil {
		return fmt.Errorf("change password update user: %w", err)
	}
	return nil
}

// nonAlphanumRe matches any character that is not a letter, digit, dash, or underscore.
var nonAlphanumRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// FindOrCreateByEmail looks up a user by email address, creating one if none
// exists. The second return value is true when a new user was created.
func (s *Service) FindOrCreateByEmail(ctx context.Context, emailAddr string) (*User, bool, error) {
	normalized := strings.ToLower(strings.TrimSpace(emailAddr))

	u, err := s.store.GetByEmail(ctx, normalized)
	if err == nil {
		return u, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, fmt.Errorf("find or create by email: %w", err)
	}

	// Derive a username from the local part of the email address.
	localPart := normalized
	if idx := strings.Index(normalized, "@"); idx >= 0 {
		localPart = normalized[:idx]
	}
	derived := nonAlphanumRe.ReplaceAllString(localPart, "_")
	if len(derived) > 64 {
		derived = derived[:64]
	}
	if derived == "" {
		derived = "user"
	}

	newUser := &User{
		Username: derived,
		Email:    normalized,
		IsActive: true,
		Roles:    "[]",
	}

	if err := s.store.Create(ctx, newUser); err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			// Append a 4-char random hex suffix and retry once.
			suffix, randErr := randomHex(2) // 2 bytes = 4 hex chars
			if randErr != nil {
				return nil, false, fmt.Errorf("find or create by email: generate suffix: %w", randErr)
			}
			newUser.ID = "" // reset so Create assigns a fresh UUID
			newUser.Username = derived + "_" + suffix
			if err2 := s.store.Create(ctx, newUser); err2 != nil {
				if errors.Is(err2, ErrEmailTaken) {
					// Race condition: another goroutine created the user — re-fetch.
					existing, fetchErr := s.store.GetByEmail(ctx, normalized)
					if fetchErr != nil {
						return nil, false, fmt.Errorf("find or create by email: re-fetch after race: %w", fetchErr)
					}
					return existing, false, nil
				}
				return nil, false, fmt.Errorf("find or create by email: create with suffix: %w", err2)
			}
			return newUser, true, nil
		}
		if errors.Is(err, ErrEmailTaken) {
			// Race condition: another goroutine created the user — re-fetch.
			existing, fetchErr := s.store.GetByEmail(ctx, normalized)
			if fetchErr != nil {
				return nil, false, fmt.Errorf("find or create by email: re-fetch after email race: %w", fetchErr)
			}
			return existing, false, nil
		}
		return nil, false, fmt.Errorf("find or create by email: create: %w", err)
	}
	return newUser, true, nil
}

// randomHex generates n random bytes and returns them as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateMagicLinkToken creates a new magic link token for the given user.
func (s *Service) CreateMagicLinkToken(ctx context.Context, userID string, ttlMinutes int) (*MagicLinkToken, error) {
	tok, err := s.tokenStore.CreateMagicLinkToken(ctx, userID, ttlMinutes)
	if err != nil {
		return nil, fmt.Errorf("user: create magic link token: %w", err)
	}
	return tok, nil
}

// ConsumeMagicLinkToken validates a magic link token and returns the associated
// user. The token is marked used atomically to prevent double-spend.
func (s *Service) ConsumeMagicLinkToken(ctx context.Context, token string) (*User, error) {
	t, err := s.tokenStore.GetMagicLinkToken(ctx, token)
	if err != nil {
		if errors.Is(err, ErrMagicLinkTokenNotFound) {
			return nil, ErrMagicLinkTokenNotFound
		}
		return nil, fmt.Errorf("user: consume magic link token get: %w", err)
	}

	if t.ExpiresAt.Before(time.Now()) {
		return nil, ErrMagicLinkTokenExpired
	}
	if t.UsedAt != nil {
		return nil, ErrMagicLinkTokenUsed
	}

	if err := s.tokenStore.MarkMagicLinkTokenUsed(ctx, token); err != nil {
		if errors.Is(err, ErrMagicLinkTokenUsed) {
			return nil, ErrMagicLinkTokenUsed
		}
		return nil, fmt.Errorf("user: consume magic link token mark used: %w", err)
	}

	u, err := s.store.GetByID(ctx, t.UserID)
	if err != nil {
		return nil, fmt.Errorf("user: consume magic link token get user: %w", err)
	}
	return u, nil
}

// DeleteExpiredMagicLinkTokens removes expired and used magic link tokens.
func (s *Service) DeleteExpiredMagicLinkTokens(ctx context.Context) error {
	if err := s.tokenStore.DeleteExpiredMagicLinkTokens(ctx); err != nil {
		return fmt.Errorf("user: delete expired magic link tokens: %w", err)
	}
	return nil
}
