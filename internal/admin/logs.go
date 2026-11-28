package admin

import "net/http"

// Log tabs. The two logs share one page and one nav entry; the tab decides
// which table is rendered.
const (
	logTabSignins = "signins"
	logTabAdmin   = "admin"
)

// logsData is the template data for the combined logs page. Exactly one of the
// nested structs is populated, matching the active tab.
type logsData struct {
	basePage
	Tab    string
	Signin securityLogData
	Admin  auditLogData
}

// auditLogData is the template data for the admin actions log tab.
type auditLogData struct {
	basePage
	Events       []*AuditEvent
	Actions      []string
	ActionFilter string
	Pager        pagination
}

// GetLogs renders the combined logs page, dispatching on ?tab=. An unknown or
// missing tab falls back to sign-ins, so a stale link still lands somewhere
// useful.
func (h *Handler) GetLogs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("tab") == logTabAdmin {
		h.GetAuditLog(w, r)
		return
	}
	h.GetSecurityLog(w, r)
}

// GetAuditLog renders the admin audit log page.
func (h *Handler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	actionFilter := q.Get("action")

	filter := AuditFilter{Action: actionFilter}
	total, err := h.audit.Count(ctx, filter)
	if err != nil {
		h.logger.Error("admin: count audit log", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	pq := cloneQuery(q)
	pq.Set("tab", logTabAdmin)
	pager := h.paginationFor(w, r, pq, "/admin/logs", "page", "per_page", total, pageSizeLogsAdmin)
	filter.Limit = pager.Size
	filter.Offset = (pager.Page - 1) * pager.Size

	events, err := h.audit.List(ctx, filter)
	if err != nil {
		h.logger.Error("admin: list audit log", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.render(w, r, "admin-logs", logsData{
		basePage: h.base(r, "logs"),
		Tab:      logTabAdmin,
		Admin: auditLogData{
			Events:       events,
			Actions:      AuditActions(),
			ActionFilter: actionFilter,
			Pager:        pager,
		},
	})
}

// redirectLogs returns a handler that forwards a legacy log URL to its tab,
// preserving any filters that came with it while replacing any conflicting tab.
func (h *Handler) redirectLogs(tab string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := "/admin/logs?tab=" + tab
		if r.URL.RawQuery != "" {
			q := r.URL.Query()
			if q.Has("tab") {
				q.Del("tab")
				if rest := q.Encode(); rest != "" {
					target += "&" + rest
				}
			} else {
				target += "&" + r.URL.RawQuery
			}
		}
		http.Redirect(w, r, target, http.StatusFound)
	}
}
