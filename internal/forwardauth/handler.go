package forwardauth

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// sessionValidator is the interface the Handler uses for session operations.
// Defined here at the consumer boundary to avoid circular dependencies.
type sessionValidator interface {
	ValidateSession(ctx context.Context, token string) (*session.Session, *user.User, error)
	RevokeSession(ctx context.Context, token string) error
}

// appResolver is the interface the Handler uses for app resolution and access checks.
// Defined here at the consumer boundary.
type appResolver interface {
	ResolveFromHost(ctx context.Context, host string) (*app.App, error)
	HasAccess(ctx context.Context, userID, appID string) (bool, error)
}

// Handler handles forward-auth requests for Nginx and Traefik.
type Handler struct {
	sessions sessionValidator
	apps     appResolver
	cfg      *config.Config
	logger   *slog.Logger
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(sessions sessionValidator, apps appResolver, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		sessions: sessions,
		apps:     apps,
		cfg:      cfg,
		logger:   logger,
	}
}

// Routes registers the forward-auth routes on the given router.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/auth/nginx", h.NginxAuth)
	r.Get("/auth/traefik", h.TraefikAuth)
	r.Get("/auth/start", h.AuthStart)
	r.Post("/auth/sign_out", h.SignOut)
}

// NginxAuth handles the Nginx auth_request forward-auth check.
// It reads the original request context from the X-Original-URL header.
func (h *Handler) NginxAuth(w http.ResponseWriter, r *http.Request) {
	originalURL := r.Header.Get("X-Original-URL")
	if originalURL == "" {
		h.logger.Warn("nginx auth: missing X-Original-URL header")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	parsed, err := url.Parse(originalURL)
	if err != nil {
		h.logger.Warn("nginx auth: malformed X-Original-URL", "url", originalURL, "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	host := stripPort(parsed.Host)
	h.checkAuth(w, r, host)
}

// TraefikAuth handles the Traefik forwardAuth forward-auth check.
// It reads the original host from the X-Forwarded-Host header.
func (h *Handler) TraefikAuth(w http.ResponseWriter, r *http.Request) {
	forwardedHost := r.Header.Get("X-Forwarded-Host")
	if forwardedHost == "" {
		h.logger.Warn("traefik auth: missing X-Forwarded-Host header")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	host := stripPort(forwardedHost)
	h.checkAuth(w, r, host)
}

// checkAuth contains the shared authentication logic used by both NginxAuth
// and TraefikAuth. It validates the session, resolves the app from the host,
// and checks the user's access.
func (h *Handler) checkAuth(w http.ResponseWriter, r *http.Request, host string) {
	ctx := r.Context()

	// Read session cookie.
	cookie, err := r.Cookie(h.cfg.Session.CookieName)
	if err != nil {
		// No cookie present — not authenticated.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Validate session.
	_, u, err := h.sessions.ValidateSession(ctx, cookie.Value)
	if err != nil {
		h.logger.Debug("forward auth: session validation failed", "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Resolve the app from the host header.
	a, err := h.apps.ResolveFromHost(ctx, host)
	if err != nil {
		h.logger.Debug("forward auth: no app for host", "host", host, "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check user access to the app.
	hasAccess, err := h.apps.HasAccess(ctx, u.ID, a.ID)
	if err != nil {
		h.logger.Error("forward auth: access check failed", "user_id", u.ID, "app_id", a.ID, "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !hasAccess {
		h.logger.Debug("forward auth: user has no access to app", "user_id", u.ID, "app_id", a.ID)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Success — set identity headers and return 200.
	isAdmin := "false"
	if u.IsAdmin {
		isAdmin = "true"
	}
	w.Header().Set("X-Passage-Username", u.Username)
	w.Header().Set("X-Passage-Email", u.Email)
	w.Header().Set("X-Passage-Name", u.Name)
	w.Header().Set("X-Passage-User-ID", u.ID)
	w.Header().Set("X-Passage-Is-Admin", isAdmin)
	w.WriteHeader(http.StatusOK)
}

// AuthStart saves the rd (return URL) in a short-lived cookie and redirects
// to the login page.
func (h *Handler) AuthStart(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")

	// Safe if it starts with "/" but NOT "//" (protocol-relative URLs like
	// //evil.example.com are treated as absolute by browsers and must be rejected).
	if rd != "" && strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//") {
		// Store the return URL in a short-lived HttpOnly cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "passage_rd",
			Value:    rd,
			Path:     "/",
			MaxAge:   300, // 5 minutes
			HttpOnly: true,
			Secure:   h.cfg.Session.CookieSecure,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(5 * time.Minute),
		})
	}
	// Always redirect to /login regardless of whether rd was valid.
	http.Redirect(w, r, "/login", http.StatusFound)
}

// SignOut revokes the current session cookie and returns 200.
func (h *Handler) SignOut(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.Session.CookieName)
	if err == nil {
		// Ignore "not found" errors — session may already be expired/deleted.
		if err := h.sessions.RevokeSession(r.Context(), cookie.Value); err != nil {
			h.logger.Debug("sign out: revoke session", "error", err)
		}
	}
	session.ClearCookie(w, h.cfg)
	w.WriteHeader(http.StatusOK)
}

// stripPort removes the port suffix from a host string, if present.
// e.g. "example.com:443" → "example.com".
func stripPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}
