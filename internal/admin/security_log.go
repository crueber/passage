package admin

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/crueber/passage/internal/authlog"
)

const (
	// securityLogPageSize is the number of events shown per page.
	securityLogPageSize = 50
	// defaultSecurityLogDays is the look-back window when none is requested.
	defaultSecurityLogDays = 30
)

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
	Page           int
	Total          int
	TotalPages     int
	PrevURL        string
	NextURL        string
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

	page := 1
	if n, err := strconv.Atoi(q.Get("page")); err == nil && n > 1 {
		page = n
	}

	filter := authlog.Filter{
		Event:    eventFilter,
		Outcome:  outcomeFilter,
		Username: usernameFilter,
		Since:    time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour),
	}

	total, err := h.authEvents.Count(ctx, filter)
	if err != nil {
		h.logger.Error("admin: count auth events", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	totalPages := (total + securityLogPageSize - 1) / securityLogPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	// Clamp an out-of-range page (for example, a stale link after retention
	// removed rows) so the table and pager stay consistent.
	if page > totalPages {
		page = totalPages
	}

	filter.Limit = securityLogPageSize
	filter.Offset = (page - 1) * securityLogPageSize

	events, err := h.authEvents.List(ctx, filter)
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
		Page:           page,
		Total:          total,
		TotalPages:     totalPages,
		Filtered:       eventFilter != "" || outcomeFilter != "" || usernameFilter != "",
	}
	if page > 1 {
		data.PrevURL = securityLogURL(eventFilter, outcomeFilter, usernameFilter, days, page-1)
	}
	if page < totalPages {
		data.NextURL = securityLogURL(eventFilter, outcomeFilter, usernameFilter, days, page+1)
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

// securityLogURL builds a pagination link that preserves the active filters.
func securityLogURL(event, outcome, username string, days, page int) string {
	q := url.Values{}
	q.Set("days", strconv.Itoa(days))
	if event != "" {
		q.Set("event", event)
	}
	if outcome != "" {
		q.Set("outcome", outcome)
	}
	if username != "" {
		q.Set("username", username)
	}
	if page > 1 {
		q.Set("page", strconv.Itoa(page))
	}
	return "/admin/logs?tab=" + logTabSignins + "&" + q.Encode()
}
