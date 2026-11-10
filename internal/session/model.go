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
	ID string
	// PublicID is a random, non-secret identifier used in admin URLs (e.g.
	// revoke links). It must never be used for authentication — the session
	// ID itself is the bearer token and must not appear in URLs or logs.
	PublicID  string
	UserID    string
	AppID     *string // nil = admin/global session
	IPAddress string
	UserAgent string
	ExpiresAt time.Time // absolute expiry, fixed at creation
	CreatedAt time.Time
	// LastUsedAt is the last time the session was seen in use. It is refreshed
	// at most once every few minutes (see Service.ValidateSession). The zero
	// value means "unknown" — callers must fall back to CreatedAt.
	LastUsedAt time.Time
}

// lastUsedOrCreated returns LastUsedAt, falling back to CreatedAt for rows
// written before last_used_at existed.
func (s *Session) lastUsedOrCreated() time.Time {
	if s.LastUsedAt.IsZero() {
		return s.CreatedAt
	}
	return s.LastUsedAt
}

// Store is the persistence interface for sessions. It is defined here, at the
// consumer boundary, as per Go convention.
type Store interface {
	Create(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, id string) (*Session, error)
	ListByUser(ctx context.Context, userID string) ([]*Session, error)
	ListAll(ctx context.Context) ([]*Session, error)
	Delete(ctx context.Context, id string) error
	DeleteByUser(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) error
	DeleteByPublicID(ctx context.Context, publicID string) error
	// TouchLastUsed sets last_used_at to now, but only when the stored value is
	// older than staleBefore. The guard keeps concurrent requests from
	// producing more than one write per throttle window.
	TouchLastUsed(ctx context.Context, id string, now, staleBefore time.Time) error
	// DeleteIdleBefore removes sessions whose last use (falling back to
	// created_at for pre-migration rows) is before cutoff.
	DeleteIdleBefore(ctx context.Context, cutoff time.Time) error
}
