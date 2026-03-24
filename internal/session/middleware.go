package session

import (
	"context"
	"net/http"
	"net/url"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/user"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const userContextKey contextKey = iota

// RequireSession returns a chi middleware that validates the session cookie and
// stores the authenticated user in the request context. If validation fails,
// the request is redirected to /login with the current URL as the `rd` param.
func RequireSession(svc *Service, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cfg.Session.CookieName)
			if err != nil {
				redirectToLogin(w, r)
				return
			}

			_, u, err := svc.ValidateSession(r.Context(), cookie.Value)
			if err != nil {
				redirectToLogin(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

// redirectToLogin redirects the client to the login page, encoding the
// current request URL as the `rd` query parameter so it can be restored
// after successful authentication.
func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	loginURL := "/login?rd=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, loginURL, http.StatusFound)
}
