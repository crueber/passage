package webauthn

import (
	"context"
	"errors"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
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

// ChallengeStorer is the interface for storing and retrieving WebAuthn challenge
// session data. Both the in-memory ChallengeStore and the SQLiteChallengeStore
// implement this interface.
//
// Entries are namespaced by ceremony — "reg:" for registration, "auth:" for
// passwordless login, "mfa:" for a second-factor assertion bound to a pending
// MFA challenge — and every Get is destructive (single-use). A ceremony can
// only be finished with the key it was begun under, so an assertion started
// for one pending sign-in cannot complete another.
type ChallengeStorer interface {
	SetRegistration(sessionID string, session gowebauthn.SessionData)
	SetAuthentication(sessionID string, session gowebauthn.SessionData)
	GetRegistration(sessionID string) (gowebauthn.SessionData, error)
	GetAuthentication(sessionID string) (gowebauthn.SessionData, error)
	// SetSecondFactor stores a second-factor assertion challenge bound to the
	// pending MFA challenge token bindKey.
	SetSecondFactor(bindKey string, session gowebauthn.SessionData)
	// GetSecondFactor retrieves and removes the second-factor ceremony begun
	// under bindKey.
	GetSecondFactor(bindKey string) (gowebauthn.SessionData, error)
	DeleteExpired(ctx context.Context) error
}
