package admin

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/crueber/passage/internal/authlog"
)

// defaultSecurityLogDays is the look-back window when none is requested.
const defaultSecurityLogDays = 30

// securityLogDayOptions returns the offered look-back windows as a fresh
// slice, in display order.
func securityLogDayOptions() []int {
	return []int{7, 30, 90}
}

// authLogReader is the minimal interface for reading authentication events.
// Defined at the consumer boundary; backed by *authlog.Store in run.go.
type authLogReader interface {
	List(ctx context.Context, f authlog.Filter) ([]*authlog.Event, error)
	Count(ctx context.Context, f authlog.Filter) (int, error)
}

// securityLogData is the template data for the authentication security log.
type securityLogData struct {
	basePage
	Events         []*authlog.Event
	EventNames     []string
	Outcomes       []string
	DaysOptions    []int
	EventFilter    string
	OutcomeFilter  string
	UsernameFilter string
	Days           int
	Pager          pagination
	Filtered       bool
}

// GetSecurityLog renders the authentication event log.
//
// Every filter value is parsed defensively: an unknown or malformed value is
// ignored and the page renders with the default, never a 500.
func (h *Handler) GetSecurityLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	eventFilter := q.Get("event")
	if !authlog.IsKnownEvent(eventFilter) {
		eventFilter = ""
	}

	outcomeFilter := q.Get("outcome")
	if !authlog.IsKnownOutcome(outcomeFilter) {
		outcomeFilter = ""
	}

	usernameFilter := q.Get("username")

	days := defaultSecurityLogDays
	if n, err := strconv.Atoi(q.Get("days")); err == nil && isSecurityLogDays(n) {
		days = n
	}

	filter := authlog.Filter{
		Event:    eventFilter,
		Outcome:  outcomeFilter,
		Username: usernameFilter,
		Since:    time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour),
	}

	total, err := h.authLog.Count(ctx, filter)
	if err != nil {
		h.logger.Error("admin: count auth events", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	pq := cloneQuery(q)
	pq.Set("tab", logTabSignins)
	pager := h.paginationFor(w, r, pq, "/admin/logs", "page", "per_page", total, pageSizeLogsSignins)

	filter.Limit = pager.Size
	filter.Offset = (pager.Page - 1) * pager.Size

	events, err := h.authLog.List(ctx, filter)
	if err != nil {
		h.logger.Error("admin: list auth events", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := securityLogData{
		Events:         events,
		EventNames:     authlog.Names(),
		Outcomes:       authlog.Outcomes(),
		DaysOptions:    securityLogDayOptions(),
		EventFilter:    eventFilter,
		OutcomeFilter:  outcomeFilter,
		UsernameFilter: usernameFilter,
		Days:           days,
		Pager:          pager,
		Filtered:       eventFilter != "" || outcomeFilter != "" || usernameFilter != "",
	}

	h.render(w, r, "admin-logs", logsData{
		basePage: h.base(r, "logs"),
		Tab:      logTabSignins,
		Signin:   data,
	})
}

// isSecurityLogDays reports whether n is one of the offered windows.
func isSecurityLogDays(n int) bool {
	for _, d := range securityLogDayOptions() {
		if d == n {
			return true
		}
	}
	return false
}
