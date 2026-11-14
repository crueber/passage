package session

import (
	"bytes"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// Handler serves the user-facing "Sessions" page: the signed-in user's own
// sessions, with per-session revoke and "sign out everywhere".
//
// Every route it registers mutates or reveals only the current user's data, so
// the router mounting it must apply RequireSession and CSRF protection.
type Handler struct {
	svc    *Service
	tmpl   *template.Template
	cfg    *config.Config
	logger *slog.Logger
}

// NewHandler creates a user-sessions Handler.
func NewHandler(svc *Service, tmpl *template.Template, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, tmpl: tmpl, cfg: cfg, logger: logger}
}

// Routes registers the user-facing session routes on the given router. The
// router must already be session-authenticated and CSRF-protected.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/sessions", h.GetSessions)
	r.Post("/sessions/revoke", h.PostRevokeSession)
	r.Post("/sessions/revoke-all", h.PostRevokeAllSessions)
}

// SessionView is one row of the sessions table, pre-computed so the template
// stays free of parsing and expiry logic.
type SessionView struct {
	PublicID   string
	Device     string
	UserAgent  string
	IPAddress  string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero = unknown (pre-migration row)
	Current    bool
}

// sessionsPageData is the template data for the sessions page.
type sessionsPageData struct {
	web.Themed
	User      *user.User
	Sessions  []SessionView
	Flash     *user.Flash
	CSRFToken string
}

// GetSessions renders the current user's active sessions.
func (h *Handler) GetSessions(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	current, _ := SessionFromContext(r.Context())

	sessions, err := h.svc.ListByUser(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("sessions: list by user", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Apply the same expiry rule validation uses so the page never offers a
	// revoke button for a session that is already dead.
	now := time.Now().UTC()
	views := make([]SessionView, 0, len(sessions))
	for _, s := range sessions {
		if h.svc.SessionExpired(r.Context(), s, now) {
			continue
		}
		views = append(views, SessionView{
			PublicID:   s.PublicID,
			Device:     DeviceSummary(s.UserAgent),
			UserAgent:  s.UserAgent,
			IPAddress:  s.IPAddress,
			CreatedAt:  s.CreatedAt,
			LastUsedAt: s.LastUsedAt,
			Current:    current != nil && current.PublicID == s.PublicID,
		})
	}

	h.render(w, r, "sessions.html", sessionsPageData{
		Themed:    web.Themed{Theme: u.Theme},
		User:      u,
		Sessions:  views,
		Flash:     flashFromCode(r.URL.Query().Get("flash")),
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// PostRevokeSession revokes one of the current user's sessions, identified by
// its public ID. The raw session ID is the bearer token and must never appear
// in a form, URL, or log line.
//
// Revoking the session making the request is equivalent to signing out: the
// cookie is cleared and the browser is sent to /login.
func (h *Handler) PostRevokeSession(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/sessions?flash=error", http.StatusFound)
		return
	}

	publicID := r.FormValue("public_id")
	if publicID == "" {
		http.Redirect(w, r, "/sessions?flash=error", http.StatusFound)
		return
	}

	// Ownership check: a public ID is not a secret, so revoking must be limited
	// to sessions the caller actually owns. Comparing against the user's own
	// list is also the only lookup the store needs.
	owned, err := h.svc.ListByUser(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("sessions: list by user for revoke", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/sessions?flash=error", http.StatusFound)
		return
	}
	var target *Session
	for _, s := range owned {
		if s.PublicID == publicID {
			target = s
			break
		}
	}
	if target == nil {
		h.logger.Warn("sessions: revoke for session not owned by user", "user_id", u.ID)
		http.Redirect(w, r, "/sessions?flash=error", http.StatusFound)
		return
	}

	if err := h.svc.RevokeSessionByPublicID(r.Context(), publicID); err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			h.logger.Error("sessions: revoke", "user_id", u.ID, "error", err)
			http.Redirect(w, r, "/sessions?flash=error", http.StatusFound)
			return
		}
	}

	// Revoking the session that made this request is a sign-out: clear the
	// cookie so the browser stops replaying a dead token. The session ID is the
	// bearer token, so it is compared, never logged or rendered.
	if cookie, err := r.Cookie(h.cfg.Session.EffectiveCookieName()); err == nil && cookie.Value == target.ID {
		ClearCookie(w, h.cfg)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/sessions?flash=revoked", http.StatusFound)
}

// PostRevokeAllSessions revokes every session the current user owns, including
// the one making the request, then clears the cookie and returns to /login.
func (h *Handler) PostRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := h.svc.RevokeAllByUser(r.Context(), u.ID); err != nil {
		h.logger.Error("sessions: revoke all", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/sessions?flash=error", http.StatusFound)
		return
	}

	ClearCookie(w, h.cfg)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// flashFromCode converts a flash query-param code into a flash message.
func flashFromCode(code string) *user.Flash {
	switch code {
	case "revoked":
		return &user.Flash{Type: "success", Message: "Session revoked."}
	case "error":
		return &user.Flash{Type: "error", Message: "An error occurred. Please try again."}
	default:
		return nil
	}
}

// render executes a named template into a buffer and writes the result to w.
// Buffering ensures a partial page is never written if execution fails.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.Error("sessions: render template", "name", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}
