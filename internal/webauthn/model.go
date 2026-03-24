package webauthn

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors for WebAuthn operations.
var (
	ErrCredentialNotFound = errors.New("webauthn: credential not found")
	ErrChallengeNotFound  = errors.New("challenge not found")
	ErrChallengeExpired   = errors.New("challenge expired")
)

// Credential represents a stored WebAuthn credential for a user.
type Credential struct {
	// ID is the base64url-encoded credential ID (TEXT primary key in DB).
	ID string

	// UserID is the UUID of the owning user.
	UserID string

	// Name is a user-assigned friendly label (may be empty).
	Name string

	// PublicKey holds the JSON-marshalled webauthn.Credential from go-webauthn.
	PublicKey []byte

	// SignCount is the authenticator sign count, used for clone detection.
	SignCount uint32

	CreatedAt  time.Time
	LastUsedAt *time.Time // nil if never used after initial registration
}

// CredentialStore is the persistence interface for WebAuthn credentials.
// Defined at the consumer boundary per Go convention.
type CredentialStore interface {
	Create(ctx context.Context, cred *Credential) error
	GetByID(ctx context.Context, id string) (*Credential, error)
	ListByUser(ctx context.Context, userID string) ([]*Credential, error)
	CountByUser(ctx context.Context, userID string) (int, error)
	UpdateSignCount(ctx context.Context, id string, newCount uint32) error
	Delete(ctx context.Context, id string) error
}
