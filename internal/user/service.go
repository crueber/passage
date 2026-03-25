package user

import (
	"context"
	"errors"
	"fmt"
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
