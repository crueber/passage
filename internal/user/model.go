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
	ErrNameTooLong          = errors.New("user: display name is too long")

	ErrMagicLinkTokenNotFound = errors.New("user: magic link token not found")
	ErrMagicLinkTokenExpired  = errors.New("user: magic link token expired")
	ErrMagicLinkTokenUsed     = errors.New("user: magic link token already used")

	ErrEmailVerificationTokenNotFound = errors.New("user: email verification token not found")
	ErrEmailVerificationTokenExpired  = errors.New("user: email verification token expired")
	ErrEmailVerificationTokenUsed     = errors.New("user: email verification token already used")

	ErrInvitationNotFound = errors.New("user: invitation not found")
	ErrInvitationExpired  = errors.New("user: invitation expired")
	ErrInvitationAccepted = errors.New("user: invitation already accepted")
	ErrSMTPNotConfigured  = errors.New("user: SMTP is not configured")
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
	// EmailVerified reports whether the account holder has proven control of
	// Email. It is informational only: it never blocks authentication, so a
	// broken or absent mail server cannot lock anyone out.
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
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

// EmailVerificationToken is a single-use, time-limited token that proves the
// account holder controls the address on the account. Email is captured at
// issue time so a token cannot verify a later, different address.
type EmailVerificationToken struct {
	Token     string
	UserID    string
	Email     string
	ExpiresAt time.Time
	UsedAt    *time.Time // nil = not yet consumed
	CreatedAt time.Time
}

// Invitation is a pending offer of an account, sent to an address that has no
// user yet. No user row exists until the recipient accepts: the invitation
// carries the address and display name, and acceptance creates the account.
type Invitation struct {
	ID         string
	Token      string
	Email      string
	Name       string
	InvitedBy  string
	ExpiresAt  time.Time
	AcceptedAt *time.Time // nil = still pending
	CreatedAt  time.Time
}

// Pending reports whether the invitation can still be accepted: not consumed
// and not past its expiry.
func (i *Invitation) Pending() bool {
	return i != nil && i.AcceptedAt == nil && time.Now().UTC().Before(i.ExpiresAt)
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
	// SetEmailVerified sets only the email_verified flag for one user. Used by
	// the verification flow and by magic-link sign-in (which proves control of
	// the address) so a concurrent profile edit cannot be clobbered.
	SetEmailVerified(ctx context.Context, id string, verified bool) error
	// SetName sets only the display name for one user, so the self-service
	// profile form cannot overwrite a concurrent admin edit to other fields.
	SetName(ctx context.Context, id, name string) error
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

	// Email verification tokens. Creating a token invalidates any earlier
	// unused token for the same user, so only the newest link works.
	CreateEmailVerificationToken(ctx context.Context, userID, emailAddr string, ttl time.Duration) (*EmailVerificationToken, error)
	GetEmailVerificationToken(ctx context.Context, token string) (*EmailVerificationToken, error)
	MarkEmailVerificationTokenUsed(ctx context.Context, token string) error

	// Invitations. Creating one invalidates any earlier pending invitation for
	// the same address, so only the newest link works. No user row is written
	// until the invitation is accepted.
	CreateInvitation(ctx context.Context, emailAddr, name, invitedBy string, ttl time.Duration) (*Invitation, error)
	GetInvitation(ctx context.Context, token string) (*Invitation, error)
	// MarkInvitationAccepted consumes the invitation atomically. It returns
	// ErrInvitationAccepted when another request already consumed it.
	MarkInvitationAccepted(ctx context.Context, token string) error
	// DeleteInvitation removes one pending invitation by ID (admin revoke).
	DeleteInvitation(ctx context.Context, id string) error
	ListPendingInvitations(ctx context.Context) ([]*Invitation, error)
	// DeleteExpiredInvitations removes invitations that expired and were never
	// accepted. Consumed rows are kept as a short audit trail.
	DeleteExpiredInvitations(ctx context.Context) error
}
