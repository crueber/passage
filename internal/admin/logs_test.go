package admin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// getLogs calls the dispatcher the way the /admin/logs route does.
func getLogs(t *testing.T, f *fixture, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	f.handler.GetLogs(rec, req)
	return rec
}

func TestGetLogs_TabSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		target     string
		wantActive string // tab label rendered as active
		wantText   string // an empty-state phrase unique to that tab
		wantAbsent string
	}{
		{
			name:       "default is sign-ins",
			target:     "/admin/logs",
			wantActive: `href="/admin/logs?tab=signins" class="tab is-active"`,
			wantText:   "No authentication events found",
			wantAbsent: "No audit log entries found",
		},
		{
			name:       "explicit sign-ins tab",
			target:     "/admin/logs?tab=signins",
			wantActive: `href="/admin/logs?tab=signins" class="tab is-active"`,
			wantText:   "No authentication events found",
			wantAbsent: "No audit log entries found",
		},
		{
			name:       "admin actions tab",
			target:     "/admin/logs?tab=admin",
			wantActive: `href="/admin/logs?tab=admin" class="tab is-active"`,
			wantText:   "No audit log entries found",
			wantAbsent: "No authentication events found",
		},
		{
			name:       "unknown tab falls back to sign-ins",
			target:     "/admin/logs?tab=nope",
			wantActive: `href="/admin/logs?tab=signins" class="tab is-active"`,
			wantText:   "No authentication events found",
			wantAbsent: "No audit log entries found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			rec := getLogs(t, f, tt.target)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want 200", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tt.wantActive) {
				t.Errorf("active tab markup missing: %q", tt.wantActive)
			}
			if !strings.Contains(body, tt.wantText) {
				t.Errorf("expected content %q missing", tt.wantText)
			}
			if strings.Contains(body, tt.wantAbsent) {
				t.Errorf("other tab's content %q leaked into this tab", tt.wantAbsent)
			}
			if !strings.Contains(body, "<title>Logs — Passage Admin</title>") {
				t.Error("page title is not the combined Logs title")
			}
		})
	}
}

// TestLegacyLogRoutesRedirect pins the compatibility redirects so old
// bookmarks and links keep working after the merge.
func TestLegacyLogRoutesRedirect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"security log", "/security-log", "/admin/logs?tab=signins"},
		{"security log with filters", "/security-log?event=login.failure&days=7", "/admin/logs?tab=signins&event=login.failure&days=7"},
		{"audit log", "/audit-log", "/admin/logs?tab=admin"},
		{"audit log with filter", "/audit-log?action=user.unlock", "/admin/logs?tab=admin&action=user.unlock"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			rec := httptest.NewRecorder()

			// The redirect handlers are unexported; drive them through the
			// routes the admin handler registers.
			router := chi.NewRouter()
			f.handler.Routes(router)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("status %d, want 302", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != tt.want {
				t.Errorf("Location = %q; want %q", got, tt.want)
			}
		})
	}
}
