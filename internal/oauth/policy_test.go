package oauth_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// policyRecorder captures authentication events emitted by the handler.
type policyRecorder struct {
	mu     sync.Mutex
	events []authlog.Event
}

func (r *policyRecorder) Record(_ context.Context, e authlog.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *policyRecorder) last() authlog.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return authlog.Event{}
	}
	return r.events[len(r.events)-1]
}

// authorizeWindow returns an HH:MM-HH:MM window containing now (offset 0) or
// excluding it (nonzero offsets).
func authorizeWindow(now time.Time, startOffset, endOffset time.Duration) string {
	start := now.Add(startOffset)
	end := now.Add(endOffset)
	return fmt.Sprintf("%02d:%02d-%02d:%02d", start.Hour(), start.Minute(), end.Hour(), end.Minute())
}

// TestHandler_Authorize_AccessPolicy pins the OAuth enforcement point: the
// app's policy is evaluated before a code is issued, a denial is the standard
// access_denied error with the fixed description, and access.denied records
// only the app slug and reason.
func TestHandler_Authorize_AccessPolicy(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "client-policy"
		plainSecret = "policy-secret"
		redirectURI = "https://example.com/cb"
	)

	now := time.Now()

	tests := []struct {
		name       string
		policy     app.App // only policy fields are read
		groups     []string
		roles      []string
		isAdmin    bool
		remoteAddr string
		wantStatus int
		wantReason string
	}{
		{
			name:       "empty policy allows",
			wantStatus: http.StatusFound,
		},
		{
			name:       "required group held",
			policy:     app.App{RequiredGroup: "platform"},
			groups:     []string{"platform"},
			wantStatus: http.StatusFound,
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
			wantStatus: http.StatusFound,
		},
		{
			name:       "required role missing",
			policy:     app.App{RequiredRole: "ops"},
			wantStatus: http.StatusForbidden,
			wantReason: "role",
		},
		{
			name:       "admin only admin allowed",
			policy:     app.App{AdminOnly: true},
			isAdmin:    true,
			wantStatus: http.StatusFound,
		},
		{
			name:       "admin only non-admin denied",
			policy:     app.App{AdminOnly: true},
			wantStatus: http.StatusForbidden,
			wantReason: "admin_only",
		},
		{
			name:       "cidr allowed",
			policy:     app.App{AllowedCIDRs: "10.0.0.0/8"},
			remoteAddr: "10.2.3.4:5555",
			wantStatus: http.StatusFound,
		},
		{
			name:       "cidr outside",
			policy:     app.App{AllowedCIDRs: "10.0.0.0/8"},
			remoteAddr: "192.0.2.10:5555",
			wantStatus: http.StatusForbidden,
			wantReason: "client_ip",
		},
		{
			name:       "hours window includes now",
			policy:     app.App{AllowedHours: authorizeWindow(now, -time.Hour, time.Hour)},
			wantStatus: http.StatusFound,
		},
		{
			name:       "hours window excludes now",
			policy:     app.App{AllowedHours: authorizeWindow(now, 2*time.Hour, 3*time.Hour)},
			wantStatus: http.StatusForbidden,
			wantReason: "hours",
		},
		{
			name:       "day denied",
			policy:     app.App{AllowedDays: fmt.Sprintf("%d", isoDay(now.AddDate(0, 0, 1)))},
			wantStatus: http.StatusForbidden,
			wantReason: "days",
		},
		{
			name: "combined rules all pass",
			policy: app.App{
				RequiredGroup: "platform",
				RequiredRole:  "ops",
				AllowedCIDRs:  "10.0.0.0/8",
				AllowedDays:   "1-7",
				AllowedHours:  authorizeWindow(now, -time.Hour, time.Hour),
			},
			groups:     []string{"platform"},
			roles:      []string{"ops"},
			remoteAddr: "10.1.1.1:9",
			wantStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
			testApp.RequiredGroup = tt.policy.RequiredGroup
			testApp.RequiredRole = tt.policy.RequiredRole
			testApp.AllowedCIDRs = tt.policy.AllowedCIDRs
			testApp.AdminOnly = tt.policy.AdminOnly
			testApp.AllowedHours = tt.policy.AllowedHours
			testApp.AllowedDays = tt.policy.AllowedDays

			testUser := &user.User{Username: "carol", Email: "carol@example.com", Name: "Carol"}
			sv := &fakeSessionValidator{}
			stack := buildHandlerTestStack(t, sv, testApp, testUser)
			sv.sess = &session.Session{ID: "sess-policy", UserID: testUser.ID, CreatedAt: now}
			sv.u = testUser

			stack.apps.tokenGroups = tt.groups
			stack.apps.tokenRoles = tt.roles
			testUser.IsAdmin = tt.isAdmin

			recorder := &policyRecorder{}
			h := oauth.NewHandler(stack.svc, sv, stack.svc.PrivateKey().Public().(*rsa.PublicKey),
				stack.svc.KeyID(), "https://auth.example.com", recorder, testConfig(), slog.Default())

			req := httptest.NewRequest(http.MethodGet,
				"/oauth/authorize?client_id="+clientID+"&redirect_uri="+redirectURI+"&response_type=code&scope=openid&state=st", nil)
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			req.AddCookie(&http.Cookie{Name: "passage_session", Value: "session-token"})
			w := httptest.NewRecorder()

			newTestRouter(h).ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus == http.StatusFound {
				if w.Header().Get("Location") == "" {
					t.Fatal("allowed authorize did not redirect to the callback")
				}
				return
			}

			var body map[string]string
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("deny body is not JSON: %v", err)
			}
			if body["error"] != "access_denied" {
				t.Errorf("error = %q, want access_denied", body["error"])
			}
			// The fixed description must not name the failing rule.
			if body["error_description"] != "The resource owner or authorization server denied the request." {
				t.Errorf("error_description = %q, want the fixed description", body["error_description"])
			}

			ev := recorder.last()
			if ev.Event != authlog.EventAccessDenied {
				t.Fatalf("event = %q, want %q", ev.Event, authlog.EventAccessDenied)
			}
			if ev.Outcome != authlog.OutcomeFailure {
				t.Errorf("event outcome = %q, want %q", ev.Outcome, authlog.OutcomeFailure)
			}
			if want := "reason=" + tt.wantReason; !strings.Contains(ev.Detail, want) {
				t.Errorf("event detail = %q, want it to contain %q", ev.Detail, want)
			}

			// No code may have been issued for a denied request.
			var codes int
			if err := stack.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_codes WHERE user_id = ?`, testUser.ID).Scan(&codes); err != nil {
				t.Fatalf("count oauth_codes: %v", err)
			}
			if codes != 0 {
				t.Errorf("oauth_codes rows after denial = %d, want 0", codes)
			}
		})
	}
}

// isoDay converts a time to its ISO weekday (Monday = 1 … Sunday = 7).
func isoDay(t time.Time) int {
	if t.Weekday() == time.Sunday {
		return 7
	}
	return int(t.Weekday())
}
