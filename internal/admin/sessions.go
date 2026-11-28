package admin

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/session"
)

// sessionRow bundles a session with its user's username for display.
type sessionRow struct {
	Session  *session.Session
	Username string
	// Device is the parsed "Browser on Platform" label, so the admin table is
	// scannable; the raw user agent stays available as a tooltip.
	Device string
}

type sessionsData struct {
	basePage
	Sessions []sessionRow
	Pager    pagination
}

// GetSessions renders the active sessions list.
func (h *Handler) GetSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessions, err := h.sessions.ListAll(ctx)
	if err != nil {
		h.logger.Error("admin: list sessions", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Load all users to build a username map.
	users, err := h.userStore.List(ctx)
	if err != nil {
		h.logger.Error("admin: list users for sessions", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	userMap := make(map[string]string, len(users))
	for _, u := range users {
		userMap[u.ID] = u.Username
	}

	rows := make([]sessionRow, len(sessions))
	for i, s := range sessions {
		rows[i] = sessionRow{
			Session:  s,
			Username: userMap[s.UserID],
			Device:   session.DeviceSummary(s.UserAgent),
		}
	}

	pager := h.paginationFor(w, r, r.URL.Query(), "/admin/sessions", "page", "per_page", len(rows), pageSizeSessions)
	h.render(w, r, "admin-sessions", sessionsData{
		basePage: h.baseQueryFlash(r, "sessions"),
		Sessions: pageItems(rows, pager),
		Pager:    pager,
	})
}

// PostRevokeSession revokes a session by its public (non-secret) identifier.
// The raw session ID is the bearer token and must never appear in URLs.
func (h *Handler) PostRevokeSession(w http.ResponseWriter, r *http.Request) {
	publicID := chi.URLParam(r, "id")
	if err := h.sessions.RevokeSessionByPublicID(r.Context(), publicID); err != nil {
		h.logger.Error("admin: revoke session", "public_id", publicID, "error", err)
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/admin/sessions?flash=error")
			return
		}
		http.Redirect(w, r, "/admin/sessions?flash=error", http.StatusFound)
		return
	}

	h.logAudit(r, AuditActionSessionRevoke, "session", publicID, "")

	// Support htmx partial response.
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<tr><td colspan="6"><em>Session revoked</em></td></tr>`)
		return
	}

	http.Redirect(w, r, "/admin/sessions?flash=revoked", http.StatusFound)
}
