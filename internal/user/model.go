package user

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors for user-related operations.
var (
	ErrNotFound             = errors.New("user: not found")
	ErrUsernameTaken        = errors.New("user: username already taken")
	ErrEmailTaken           = errors.New("user: email already taken")
	ErrInvalidCredentials   = errors.New("user: invalid credentials")
	ErrUserInactive         = errors.New("user: account is inactive")
	ErrRegistrationDisabled = errors.New("user: registration is disabled")
	ErrTokenExpired         = errors.New("user: reset token has expired")
	ErrTokenUsed            = errors.New("user: reset token has already been used")
	ErrPasswordTooShort     = errors.New("user: password must be at least 8 characters")
	ErrUsernameRequired     = errors.New("user: username is required")
	ErrEmailRequired        = errors.New("user: email is required")

	ErrMagicLinkTokenNotFound = errors.New("user: magic link token not found")
	ErrMagicLinkTokenExpired  = errors.New("user: magic link token expired")
	ErrMagicLinkTokenUsed     = errors.New("user: magic link token already used")
)

// User represents a Passage user account.
type User struct {
	ID           string
	Username     string
	Email        string
	Name         string
	PasswordHash string
	IsAdmin      bool
	IsActive     bool
	Roles        string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ResetToken represents a password reset token.
type ResetToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// MagicLinkToken is a single-use, time-limited token that authenticates a user
// by clicking a link sent to their email address.
type MagicLinkToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time // nil = not yet consumed
	CreatedAt time.Time
}

// Store is the persistence interface for users. It is defined here, at the
// consumer boundary, as per Go convention.
type Store interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	List(ctx context.Context) ([]*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
	// HasAdmin reports whether at least one admin user exists in the database.
	// Used at startup to determine whether the /setup endpoint should be active.
	HasAdmin(ctx context.Context) (bool, error)
}

// TokenStore is the persistence interface for password reset tokens. It is
// defined here, at the consumer boundary, as per Go convention.
type TokenStore interface {
	// CreateResetToken generates 32 bytes from crypto/rand, stores the token
	// with a 1-hour expiry for the given userID, and returns the token string.
	CreateResetToken(ctx context.Context, userID string) (string, error)
	GetResetToken(ctx context.Context, token string) (*ResetToken, error)
	MarkResetTokenUsed(ctx context.Context, token string) error

	// Magic link tokens.
	CreateMagicLinkToken(ctx context.Context, userID string, ttlMinutes int) (*MagicLinkToken, error)
	GetMagicLinkToken(ctx context.Context, token string) (*MagicLinkToken, error)
	MarkMagicLinkTokenUsed(ctx context.Context, token string) error
	DeleteExpiredMagicLinkTokens(ctx context.Context) error
}
