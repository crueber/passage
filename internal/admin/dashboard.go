package admin

import (
	"net/http"

	"github.com/crueber/passage/internal/authlog"
)

type dashboardData struct {
	basePage
	UserCount    int
	AppCount     int
	SessionCount int
	// Recent is the newest handful of authentication events, so the landing
	// page answers "did that sign-in arrive?" without opening the log.
	Recent []*authlog.Event
}

// GetDashboard renders the admin dashboard with summary counts.
func (h *Handler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userCount, err := h.userStore.Count(ctx)
	if err != nil {
		h.logger.Error("admin: dashboard count users", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	appCount, err := h.apps.Count(ctx)
	if err != nil {
		h.logger.Error("admin: dashboard count apps", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	sessionCount, err := h.sessions.CountActive(ctx)
	if err != nil {
		h.logger.Error("admin: dashboard count sessions", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// A failure to read recent events must not take down the dashboard; the
	// counts are still useful on their own.
	var recent []*authlog.Event
	if h.authLog != nil {
		recent, err = h.authLog.List(ctx, authlog.Filter{Limit: 8})
		if err != nil {
			h.logger.Warn("admin: dashboard recent events", "error", err)
			recent = nil
		}
	}

	h.render(w, r, "admin-dashboard", dashboardData{
		basePage:     h.base(r, "dashboard"),
		UserCount:    userCount,
		AppCount:     appCount,
		SessionCount: sessionCount,
		Recent:       recent,
	})
}
