package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/settings"
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

// SessionCounter counts session lifecycle events for the metrics endpoint.
// It is optional: nil disables counting, and an implementation must return
// immediately — it is called on the sign-in and sign-out paths, where a
// metrics failure must never fail or delay authentication.
type SessionCounter interface {
	// SessionCreated is called once per session that was written to the store.
	SessionCreated()
	// SessionRevoked is called once per explicit revoke operation that
	// succeeded. A bulk revoke counts as one operation, not as one per row,
	// and expiry sweeps are not revokes.
	SessionRevoked()
}

// Service implements business logic for session management.
type Service struct {
	store    Store
	users    userGetter
	settings settingsReader    // may be nil; used to read session_duration_hours from DB
	apps     appDurationReader // may be nil; used for per-app duration overrides
	cfg      *config.Config
	logger   *slog.Logger
	counter  SessionCounter // may be nil; optional metrics hook
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

// SetSessionCounter installs the optional session metrics counter. It must be
// called before the server starts serving requests.
func (s *Service) SetSessionCounter(counter SessionCounter) {
	s.counter = counter
}

// countCreated reports a created session to the metrics counter, if any.
func (s *Service) countCreated() {
	if s.counter != nil {
		s.counter.SessionCreated()
	}
}

// countRevoked reports a successful revoke to the metrics counter, if any.
func (s *Service) countRevoked() {
	if s.counter != nil {
		s.counter.SessionRevoked()
	}
}

// sessionDurationHours returns the effective session duration in hours for the
// given app (nil = global/admin session). Resolution order:
//  1. App-level override (apps.GetSessionDurationHours > 0)
//  2. An explicit session.duration_hours from the config file or environment
//  3. The global admin setting (session_duration_hours in the settings store)
//  4. cfg.Session.DurationHours (the default)
func (s *Service) sessionDurationHours(ctx context.Context, appID *string) int {
	// 1. Per-app override.
	if appID != nil && s.apps != nil {
		hours, err := s.apps.GetSessionDurationHours(ctx, *appID)
		if err == nil && hours > 0 {
			return hours
		}
		// On error (app deleted mid-request, etc.) fall through silently.
	}

	// 2./3. The stored setting, then the startup snapshot as the fallback.
	return settings.Int(ctx, s.settings, settings.SessionDurationHours, s.cfg.Session.DurationHours, 1, 8760)
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

// clientIP strips the source port from an address like "192.168.1.5:54321", so
// session lists show the device's address rather than a fresh port per sign-in.
// A bare host (or anything unparseable) is returned unchanged.
func clientIP(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
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
		IPAddress:  clientIP(ip),
		UserAgent:  ua,
		ExpiresAt:  now.Add(time.Duration(hours) * time.Hour),
		CreatedAt:  now,
		LastUsedAt: now,
	}

	if err := s.store.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	s.countCreated()
	return sess, nil
}

// idleTimeout reads the current idle window from live settings, falling back to
// the startup config snapshot when no settings store is wired (tests).
func (s *Service) idleTimeout(ctx context.Context) time.Duration {
	minutes := s.cfg.Session.IdleTimeoutMinutes
	if s.settings != nil {
		minutes = settings.Int(ctx, s.settings, settings.SessionIdleTimeoutMinutes, minutes, 0, 8760)
	}
	return time.Duration(minutes) * time.Minute
}

// SessionExpired reports whether the session is past its absolute expiry or has
// been idle longer than the configured idle window. A zero idle window disables
// the idle half of the check, leaving only the absolute expiry.
//
// Exported so user-facing handlers can filter the sessions they list with
// exactly the rule validation applies.
func (s *Service) SessionExpired(ctx context.Context, sess *Session, now time.Time) bool {
	if sess.ExpiresAt.Before(now) {
		return true
	}
	idle := s.idleTimeout(ctx)
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
	if idle := s.idleTimeout(ctx); idle > 0 && now.Sub(sess.lastUsedOrCreated()) > idle {
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
	s.countRevoked()
	return nil
}

// RevokeSessionByPublicID deletes a session by its public (non-secret)
// identifier. Used by the admin revoke endpoint so the bearer token never
// appears in URLs or access logs.
func (s *Service) RevokeSessionByPublicID(ctx context.Context, publicID string) error {
	if err := s.store.DeleteByPublicID(ctx, publicID); err != nil {
		return fmt.Errorf("revoke session by public id: %w", err)
	}
	s.countRevoked()
	return nil
}

// RevokeAllByUser deletes all sessions for the given user ID.
func (s *Service) RevokeAllByUser(ctx context.Context, userID string) error {
	if err := s.store.DeleteByUser(ctx, userID); err != nil {
		return fmt.Errorf("revoke all sessions by user: %w", err)
	}
	s.countRevoked()
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
