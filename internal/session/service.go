package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/user"
)

// userGetter is the minimal interface needed to look up a user by ID.
// Defined here at the consumer boundary.
type userGetter interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
}

// settingsReader is the minimal interface needed to read a single setting.
// Defined here at the consumer boundary to avoid an import cycle with the
// admin package.
type settingsReader interface {
	Get(ctx context.Context, key string) (string, error)
}

// appDurationReader is the minimal interface needed to read the per-app
// session duration override. Defined here at the consumer boundary to avoid
// importing the concrete app.App type.
type appDurationReader interface {
	GetSessionDurationHours(ctx context.Context, appID string) (int, error)
}

// Service implements business logic for session management.
type Service struct {
	store    Store
	users    userGetter
	settings settingsReader    // may be nil; used to read session_duration_hours from DB
	apps     appDurationReader // may be nil; used for per-app duration overrides
	cfg      *config.Config
	logger   *slog.Logger
}

// NewService creates a new Service with the given dependencies.
// settings may be nil; apps may be nil. When non-nil, each is consulted for
// session duration before falling back to cfg.Session.DurationHours.
func NewService(store Store, users userGetter, settings settingsReader, apps appDurationReader, cfg *config.Config, logger *slog.Logger) *Service {
	return &Service{
		store:    store,
		users:    users,
		settings: settings,
		apps:     apps,
		cfg:      cfg,
		logger:   logger,
	}
}

// sessionDurationHours returns the effective session duration in hours for the
// given app (nil = global/admin session). Resolution order:
//  1. App-level override (apps.GetSessionDurationHours > 0)
//  2. Global DB setting (session_duration_hours key in settings)
//  3. cfg.Session.DurationHours (config-file / env-var default)
func (s *Service) sessionDurationHours(ctx context.Context, appID *string) int {
	// 1. Per-app override.
	if appID != nil && s.apps != nil {
		hours, err := s.apps.GetSessionDurationHours(ctx, *appID)
		if err == nil && hours > 0 {
			return hours
		}
		// On error (app deleted mid-request, etc.) fall through silently.
	}

	// 2. Global DB setting.
	if s.settings != nil {
		val, err := s.settings.Get(ctx, "session_duration_hours")
		if err == nil && val != "" {
			n, err := strconv.Atoi(val)
			if err == nil && n > 0 {
				return n
			}
		}
	}

	// 3. Config fallback.
	return s.cfg.Session.DurationHours
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

// lastUsedTouchInterval is the minimum time between two last_used_at writes
// for one session. It caps the write load of idle tracking at one UPDATE per
// session per interval, no matter how many requests the session makes.
const lastUsedTouchInterval = 5 * time.Minute

// NewSession creates a new session for the given user. The session token is a
// 32-byte random value encoded as hex, as is the public (non-secret) URL
// identifier used by the revoke endpoints. Expiry is resolved by
// sessionDurationHours (per-app override → global DB setting → config).
func (s *Service) NewSession(ctx context.Context, userID string, appID *string, ip, ua string) (*Session, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}
	token := hex.EncodeToString(b)

	pub := make([]byte, 32)
	if _, err := rand.Read(pub); err != nil {
		return nil, fmt.Errorf("generate session public id: %w", err)
	}
	publicID := hex.EncodeToString(pub)

	hours := s.sessionDurationHours(ctx, appID)
	now := time.Now().UTC()
	sess := &Session{
		ID:         token,
		PublicID:   publicID,
		UserID:     userID,
		AppID:      appID,
		IPAddress:  ip,
		UserAgent:  ua,
		ExpiresAt:  now.Add(time.Duration(hours) * time.Hour),
		CreatedAt:  now,
		LastUsedAt: now,
	}

	if err := s.store.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	return sess, nil
}

// SessionExpired reports whether the session is past its absolute expiry or has
// been idle longer than the configured idle window. A zero idle window disables
// the idle half of the check, leaving only the absolute expiry.
//
// Exported so user-facing handlers can filter the sessions they list with
// exactly the rule validation applies.
func (s *Service) SessionExpired(sess *Session, now time.Time) bool {
	if sess.ExpiresAt.Before(now) {
		return true
	}
	idle := s.cfg.Session.IdleTimeout()
	if idle <= 0 {
		return false
	}
	return now.Sub(sess.lastUsedOrCreated()) > idle
}

// ValidateSession looks up the session, checks it is not expired (absolutely or
// because of the idle window), and returns the session and the associated user.
// Returns ErrSessionExpired if expired. Returns user.ErrUserInactive if the
// user account is disabled.
//
// On a successful validation the session's last_used_at is refreshed at most
// once per lastUsedTouchInterval.
func (s *Service) ValidateSession(ctx context.Context, token string) (*Session, *user.User, error) {
	sess, err := s.store.GetByID(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("validate session: %w", err)
	}

	now := time.Now().UTC()

	if sess.ExpiresAt.Before(now) {
		// Opportunistically clean up expired sessions; ignore errors.
		if err := s.store.DeleteExpired(ctx); err != nil {
			s.logger.Warn("session cleanup failed", "error", err)
		}
		return nil, nil, ErrSessionExpired
	}

	// Idle timeout: an unused session is invalid before its absolute expiry.
	// Delete this one row — the hourly sweeper clears the rest.
	if idle := s.cfg.Session.IdleTimeout(); idle > 0 && now.Sub(sess.lastUsedOrCreated()) > idle {
		if err := s.store.Delete(ctx, sess.ID); err != nil && !errors.Is(err, ErrSessionNotFound) {
			s.logger.Warn("session: delete idle session", "error", err)
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

	s.touchLastUsed(ctx, sess, now)

	return sess, u, nil
}

// touchLastUsed refreshes the session's last_used_at, throttled to one write
// per lastUsedTouchInterval. The store adds a conditional WHERE guard so
// concurrent requests cannot exceed that rate either. Failures are logged and
// ignored: idle tracking must never fail a valid request.
//
// Neither the session ID nor any part of it is logged — it is the bearer token.
func (s *Service) touchLastUsed(ctx context.Context, sess *Session, now time.Time) {
	if last := sess.lastUsedOrCreated(); !last.IsZero() && now.Sub(last) < lastUsedTouchInterval {
		return
	}
	if err := s.store.TouchLastUsed(ctx, sess.ID, now, now.Add(-lastUsedTouchInterval)); err != nil {
		s.logger.Warn("session: touch last used failed", "user_id", sess.UserID, "error", err)
	}
}

// RevokeSession deletes a session by token.
func (s *Service) RevokeSession(ctx context.Context, token string) error {
	if err := s.store.Delete(ctx, token); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeSessionByPublicID deletes a session by its public (non-secret)
// identifier. Used by the admin revoke endpoint so the bearer token never
// appears in URLs or access logs.
func (s *Service) RevokeSessionByPublicID(ctx context.Context, publicID string) error {
	if err := s.store.DeleteByPublicID(ctx, publicID); err != nil {
		return fmt.Errorf("revoke session by public id: %w", err)
	}
	return nil
}

// RevokeAllByUser deletes all sessions for the given user ID.
func (s *Service) RevokeAllByUser(ctx context.Context, userID string) error {
	if err := s.store.DeleteByUser(ctx, userID); err != nil {
		return fmt.Errorf("revoke all sessions by user: %w", err)
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
		Name:     cfg.Session.EffectiveCookieName(),
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
		Name:     cfg.Session.EffectiveCookieName(),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
