package session

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/user"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	userContextKey contextKey = iota
	sessionContextKey
)

// RequireSession returns a chi middleware that validates the session cookie and
// stores the authenticated user and session in the request context. If
// validation fails (missing, expired, idle, revoked, or the user is inactive)
// the session cookie is cleared and the request is redirected to /login with
// the current URL as the `rd` param.
func RequireSession(svc *Service, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cfg.Session.EffectiveCookieName())
			if err != nil {
				redirectToLogin(w, r)
				return
			}

			sess, u, err := svc.ValidateSession(r.Context(), cookie.Value)
			if err != nil {
				// Drop the cookie only when it can never work again (revoked,
				// expired, idle, inactive user). A transient DB error must not
				// sign the user out of every tab.
				if sessionIsGone(err) {
					ClearCookie(w, cfg)
				}
				redirectToLogin(w, r)
				return
			}

			ctx := WithSession(WithUser(r.Context(), u), sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sessionIsGone reports whether a validation error means the presented session
// is permanently unusable, as opposed to a transient lookup failure.
func sessionIsGone(err error) bool {
	return errors.Is(err, ErrSessionNotFound) ||
		errors.Is(err, ErrSessionExpired) ||
		errors.Is(err, user.ErrUserInactive)
}

// WithUser returns a new context with the given user stored under the session
// user context key. This allows the admin middleware to store an authenticated
// admin user in the context using the same key as RequireSession, so that
// session.UserFromContext works downstream in admin handlers.
func WithUser(ctx context.Context, u *user.User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// UserFromContext retrieves the authenticated user from the context.
// Returns nil, false if no user is present.
func UserFromContext(ctx context.Context) (*user.User, bool) {
	u, ok := ctx.Value(userContextKey).(*user.User)
	return u, ok
}

// WithSession returns a new context with the given session stored under the
// session context key. RequireSession calls it so handlers can identify the
// current session (e.g. to mark "This device" or to revoke it).
func WithSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, sess)
}

// SessionFromContext retrieves the current session from the context.
// Returns nil, false if no session is present.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	sess, ok := ctx.Value(sessionContextKey).(*Session)
	return sess, ok
}

// redirectToLogin redirects the client to the login page, encoding the
// current request URL as the `rd` query parameter so it can be restored
// after successful authentication.
func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	loginURL := "/login?rd=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, loginURL, http.StatusFound)
}
