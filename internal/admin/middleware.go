package admin

import (
	"context"
	"net/http"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// sessionValidator is the minimal interface needed to validate a session token
// and retrieve the associated user. Defined at the consumer boundary.
type sessionValidator interface {
	ValidateSession(ctx context.Context, token string) (*session.Session, *user.User, error)
}

// RequireAdmin returns a chi middleware that requires a valid admin session.
// If the session is missing or invalid, or the user is not an admin, the
// request is redirected to /login. We redirect (rather than 403) to avoid
// leaking the existence of the admin interface to unauthenticated requests.
func RequireAdmin(sessionSvc sessionValidator, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cfg.Session.CookieName)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			_, u, err := sessionSvc.ValidateSession(r.Context(), cookie.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			if !u.IsAdmin {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			// Store the admin user in the context using the same key as
			// session.UserFromContext so downstream handlers can retrieve it.
			ctx := session.WithUser(r.Context(), u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
