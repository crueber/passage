package session

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors for session-related operations.
var (
	ErrSessionNotFound = errors.New("session: not found")
	ErrSessionExpired  = errors.New("session: session has expired")
)

// Session represents an authenticated user session.
type Session struct {
	ID        string
	UserID    string
	AppID     *string // nil = admin/global session
	IPAddress string
	UserAgent string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Store is the persistence interface for sessions. It is defined here, at the
// consumer boundary, as per Go convention.
type Store interface {
	Create(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, id string) (*Session, error)
	ListByUser(ctx context.Context, userID string) ([]*Session, error)
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}
