package forwardauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
)

// recordingAuthEvents captures authentication events emitted by the handler so
// tests can assert the access.denied event and its reason.
type recordingAuthEvents struct {
	mu     sync.Mutex
	events []authlog.Event
}

func (r *recordingAuthEvents) Record(_ context.Context, e authlog.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// last returns the most recent recorded event, or an empty event.
func (r *recordingAuthEvents) last() authlog.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return authlog.Event{}
	}
	return r.events[len(r.events)-1]
}

// windowAround returns an "HH:MM-HH:MM" window that contains now when offset is
// zero and excludes it otherwise. Both endpoints are inclusive in the policy.
func windowAround(now time.Time, startOffset, endOffset time.Duration) string {
	start := now.Add(startOffset)
	end := now.Add(endOffset)
	return fmt.Sprintf("%02d:%02d-%02d:%02d", start.Hour(), start.Minute(), end.Hour(), end.Minute())
}

// TestNginxAuth_AccessPolicy exercises the forward-auth enforcement point: the
// handler must return 403 for a policy denial, must not leak the reason, and
// must record access.denied with the reason token.
func TestNginxAuth_AccessPolicy(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name       string
		policy     app.App // only the policy fields are read
		remoteAddr string
		groups     []string
		roles      []string
		inherit    bool // groups come from a role, not a direct assignment
		isAdmin    bool
		clearAddr  bool
		wantStatus int
		wantReason string
	}{
		{
			name:       "empty policy allows",
			policy:     app.App{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "required group held",
			policy:     app.App{RequiredGroup: "platform"},
			groups:     []string{"platform"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "required group missing",
			policy:     app.App{RequiredGroup: "platform"},
			groups:     []string{"devs"},
			wantStatus: http.StatusForbidden,
			wantReason: "group",
		},
		{
			name:       "required role held",
			policy:     app.App{RequiredRole: "ops"},
			roles:      []string{"ops"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "required role missing",
			policy:     app.App{RequiredRole: "ops"},
			roles:      []string{"viewer"},
			wantStatus: http.StatusForbidden,
			wantReason: "role",
		},
		{
			name:       "role grants its group",
			policy:     app.App{RequiredGroup: "platform"},
			roles:      []string{"ops"},
			groups:     []string{"platform"}, // effective, inherited through the role
			inherit:    true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "admin only admin allowed",
			policy:     app.App{AdminOnly: true},
			isAdmin:    true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "admin only non-admin denied",
			policy:     app.App{AdminOnly: true},
			wantStatus: http.StatusForbidden,
			wantReason: "admin_only",
		},
		{
			name:       "admin is not exempt from cidr",
			policy:     app.App{AdminOnly: true, AllowedCIDRs: "10.0.0.0/8"},
			isAdmin:    true,
			remoteAddr: "192.0.2.10:1234",
			wantStatus: http.StatusForbidden,
			wantReason: "client_ip",
		},
		{
			name:       "cidr allowed",
			policy:     app.App{AllowedCIDRs: "10.0.0.0/8, 2001:db8::/32"},
			remoteAddr: "10.1.2.3:5555",
			wantStatus: http.StatusOK,
		},
		{
			name:       "cidr v6 allowed",
			policy:     app.App{AllowedCIDRs: "2001:db8::/32"},
			remoteAddr: "[2001:db8:1::7]:443",
			wantStatus: http.StatusOK,
		},
		{
			name:       "cidr outside",
			policy:     app.App{AllowedCIDRs: "10.0.0.0/8"},
			remoteAddr: "192.0.2.10:1234",
			wantStatus: http.StatusForbidden,
			wantReason: "client_ip",
		},
		{
			name:       "cidr with empty client address fails closed",
			policy:     app.App{AllowedCIDRs: "10.0.0.0/8"},
			clearAddr:  true,
			wantStatus: http.StatusForbidden,
			wantReason: "",
		},
		{
			name:       "hours window includes now",
			policy:     app.App{AllowedHours: windowAround(now, -time.Hour, time.Hour)},
			wantStatus: http.StatusOK,
		},
		{
			name:       "hours window excludes now",
			policy:     app.App{AllowedHours: windowAround(now, 2*time.Hour, 3*time.Hour)},
			wantStatus: http.StatusForbidden,
			wantReason: "hours",
		},
		{
			name:       "today is allowed",
			policy:     app.App{AllowedDays: fmt.Sprintf("%d", isoWeekday(now))},
			wantStatus: http.StatusOK,
		},
		{
			name:       "tomorrow is denied",
			policy:     app.App{AllowedDays: fmt.Sprintf("%d", isoWeekday(now.AddDate(0, 0, 1)))},
			wantStatus: http.StatusForbidden,
			wantReason: "days",
		},
		{
			name:       "weekday range including today",
			policy:     app.App{AllowedDays: "1-7"},
			wantStatus: http.StatusOK,
		},
		{
			name: "combined rules all pass",
			policy: app.App{
				RequiredGroup: "platform",
				RequiredRole:  "ops",
				AllowedCIDRs:  "10.0.0.0/8",
				AllowedDays:   "1-7",
				AllowedHours:  windowAround(now, -time.Hour, time.Hour),
			},
			groups:     []string{"platform"},
			roles:      []string{"ops"},
			remoteAddr: "10.9.8.7:1000",
			wantStatus: http.StatusOK,
		},
		{
			name: "combined rules fail on cidr",
			policy: app.App{
				RequiredGroup: "platform",
				AllowedCIDRs:  "10.0.0.0/8",
			},
			groups:     []string{"platform"},
			remoteAddr: "192.0.2.10:1000",
			wantStatus: http.StatusForbidden,
			wantReason: "client_ip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			deps := setupDeps(t)

			u, token := createUserAndSession(t, deps, "policy"+strings.ReplaceAll(tt.name, " ", ""))
			if tt.isAdmin {
				u.IsAdmin = true
				if err := deps.userStore.Update(ctx, u); err != nil {
					t.Fatalf("make user admin: %v", err)
				}
			}

			slug := "policy-" + strings.ReplaceAll(tt.name, " ", "-")
			a := createApp(t, deps, slug, slug+".home.example.com")
			a.RequiredGroup = tt.policy.RequiredGroup
			a.RequiredRole = tt.policy.RequiredRole
			a.AllowedCIDRs = tt.policy.AllowedCIDRs
			a.AdminOnly = tt.policy.AdminOnly
			a.AllowedHours = tt.policy.AllowedHours
			a.AllowedDays = tt.policy.AllowedDays
			if err := deps.appSvc.Update(ctx, a); err != nil {
				t.Fatalf("Update app policy: %v", err)
			}

			if err := deps.appSvc.GrantAccess(ctx, u.ID, a.ID); err != nil {
				t.Fatalf("GrantAccess: %v", err)
			}

			// Direct user→group and user→role assignments. Effective groups
			// include role-inherited groups, which the handler resolves.
			var firstRole *app.Role
			for _, name := range tt.roles {
				ro := &app.Role{AppID: a.ID, Name: name}
				if err := deps.appSvc.CreateRole(ctx, ro); err != nil {
					t.Fatalf("CreateRole %q: %v", name, err)
				}
				if err := deps.appSvc.AssignUserRole(ctx, u.ID, a.ID, ro.ID); err != nil {
					t.Fatalf("AssignUserRole %q: %v", name, err)
				}
				if firstRole == nil {
					firstRole = ro
				}
			}
			for _, name := range tt.groups {
				g := &app.Group{AppID: a.ID, Name: name}
				if err := deps.appSvc.CreateGroup(ctx, g); err != nil {
					t.Fatalf("CreateGroup %q: %v", name, err)
				}
				if tt.inherit && firstRole != nil {
					if err := deps.appSvc.AssignGroupToRole(ctx, firstRole.ID, g.ID); err != nil {
						t.Fatalf("AssignGroupToRole %q: %v", name, err)
					}
					continue
				}
				if err := deps.appSvc.AssignUserGroup(ctx, u.ID, a.ID, g.ID); err != nil {
					t.Fatalf("AssignUserGroup %q: %v", name, err)
				}
			}

			r := httptest.NewRequest(http.MethodGet, "/auth/nginx", nil)
			r.Header.Set("X-Original-URL", "https://"+slug+".home.example.com/page")
			if tt.remoteAddr != "" {
				r.RemoteAddr = tt.remoteAddr
			}
			if tt.clearAddr {
				r.RemoteAddr = ""
			}
			r.AddCookie(&http.Cookie{Name: deps.cfg.Session.CookieName, Value: token})
			w := httptest.NewRecorder()

			newRouter(deps.handler).ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus == http.StatusOK {
				checkHeader(t, w, "X-Passage-Username", u.Username)
				if len(deps.authEvents.events) != 0 {
					t.Errorf("allowed request recorded %d auth events, want 0", len(deps.authEvents.events))
				}
				return
			}

			// A denial must not leak the policy reason, the username or the
			// identity headers into the response.
			body := w.Body.String()
			for _, leak := range []string{"reason=", u.Username, "group", "cidr", "hours", "days"} {
				if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
					t.Errorf("denied body leaks %q: %q", leak, body)
				}
			}
			for _, h := range []string{"X-Passage-Username", "X-Passage-User-ID", "X-Passage-Is-Admin"} {
				if got := w.Header().Get(h); got != "" {
					t.Errorf("denied response set identity header %s = %q", h, got)
				}
			}

			if tt.wantReason == "" {
				return // fail-closed evaluation error: logged, but no policy event
			}
			ev := deps.authEvents.last()
			if ev.Event != authlog.EventAccessDenied {
				t.Fatalf("event = %q, want %q", ev.Event, authlog.EventAccessDenied)
			}
			if ev.Outcome != authlog.OutcomeFailure {
				t.Errorf("event outcome = %q, want %q", ev.Outcome, authlog.OutcomeFailure)
			}
			if ev.Username != u.Username {
				t.Errorf("event username = %q, want %q", ev.Username, u.Username)
			}
			if !strings.Contains(ev.Detail, "reason="+tt.wantReason) {
				t.Errorf("event detail = %q, want it to name reason=%s", ev.Detail, tt.wantReason)
			}
			if !strings.Contains(ev.Detail, "app="+slug) {
				t.Errorf("event detail = %q, want it to name app=%s", ev.Detail, slug)
			}
		})
	}
}

// isoWeekday converts a time.Weekday to ISO numbering (Monday = 1 … Sunday = 7).
func isoWeekday(t time.Time) int {
	if t.Weekday() == time.Sunday {
		return 7
	}
	return int(t.Weekday())
}
