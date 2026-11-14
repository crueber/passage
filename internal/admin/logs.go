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

// redirectLogs returns a handler that forwards a legacy log URL to its tab,
// preserving any filters that came with it.
func (h *Handler) redirectLogs(tab string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := "/admin/logs?tab=" + tab
		if r.URL.RawQuery != "" {
			target += "&" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusFound)
	}
}
