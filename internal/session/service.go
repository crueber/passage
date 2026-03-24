package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/user"
)

// userGetter is the minimal interface needed to look up a user by ID.
// Defined here at the consumer boundary.
type userGetter interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
}

// Service implements business logic for session management.
type Service struct {
	store  Store
	users  userGetter
	cfg    *config.Config
	logger *slog.Logger
}

// NewService creates a new Service with the given dependencies.
func NewService(store Store, users userGetter, cfg *config.Config, logger *slog.Logger) *Service {
	return &Service{
		store:  store,
		users:  users,
		cfg:    cfg,
		logger: logger,
	}
}

// CreateSession creates a new session and returns the token string and expiry
// time. This method satisfies the user.sessionCreator interface, which requires
// returning primitives to avoid an import cycle.
func (s *Service) CreateSession(ctx context.Context, userID string, appID *string, ip, ua string) (string, time.Time, error) {
	sess, err := s.NewSession(ctx, userID, appID, ip, ua)
	if err != nil {
		return "", time.Time{}, err
	}
	return sess.ID, sess.ExpiresAt, nil
}

// NewSession creates a new session for the given user. The session token is a
// 32-byte random value encoded as hex. Expiry is derived from cfg.Session.DurationHours.
func (s *Service) NewSession(ctx context.Context, userID string, appID *string, ip, ua string) (*Session, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}
	token := hex.EncodeToString(b)

	now := time.Now().UTC()
	sess := &Session{
		ID:        token,
		UserID:    userID,
		AppID:     appID,
		IPAddress: ip,
		UserAgent: ua,
		ExpiresAt: now.Add(time.Duration(s.cfg.Session.DurationHours) * time.Hour),
		CreatedAt: now,
	}

	if err := s.store.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	return sess, nil
}

// ValidateSession looks up the session, checks it is not expired, and returns
// the session and the associated user. Returns ErrSessionExpired if expired.
// Returns user.ErrUserInactive if the user account is disabled.
func (s *Service) ValidateSession(ctx context.Context, token string) (*Session, *user.User, error) {
	sess, err := s.store.GetByID(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("validate session: %w", err)
	}

	if sess.ExpiresAt.Before(time.Now().UTC()) {
		// Opportunistically clean up expired sessions; ignore errors.
		if err := s.store.DeleteExpired(ctx); err != nil {
			s.logger.Warn("session cleanup failed", "error", err)
		}
		return nil, nil, ErrSessionExpired
	}

	u, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("validate session get user: %w", err)
	}

	if !u.IsActive {
		return nil, nil, user.ErrUserInactive
	}

	return sess, u, nil
}

// RevokeSession deletes a session by token.
func (s *Service) RevokeSession(ctx context.Context, token string) error {
	if err := s.store.Delete(ctx, token); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// ListAll returns all sessions ordered by creation time descending.
// It delegates directly to the store.
func (s *Service) ListAll(ctx context.Context) ([]*Session, error) {
	sessions, err := s.store.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("list all sessions: %w", err)
	}
	return sessions, nil
}

// ListByUser returns all sessions for the given user, ordered by creation
// time descending. It delegates directly to the store.
func (s *Service) ListByUser(ctx context.Context, userID string) ([]*Session, error) {
	sessions, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions by user: %w", err)
	}
	return sessions, nil
}

// SetCookie writes the session cookie to the response.
func SetCookie(w http.ResponseWriter, token string, expiresAt time.Time, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Session.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie writes an expired cookie to clear the session cookie.
func ClearCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Session.CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
