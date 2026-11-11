package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/authlog"
)

// appendAuthEvent writes one event through the fixture's store.
func appendAuthEvent(t *testing.T, f *fixture, e authlog.Event) {
	t.Helper()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if err := f.authStore.Append(context.Background(), &e); err != nil {
		t.Fatalf("append auth event: %v", err)
	}
}

// getSecurityLog calls the handler directly and returns the recorded response.
func getSecurityLog(t *testing.T, f *fixture, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	f.handler.GetSecurityLog(rec, req)
	return rec
}

func TestGetSecurityLog_EmptyState(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := getSecurityLog(t, f, "/admin/security-log")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	for _, needle := range []string{
		"<title>Logs — Passage Admin</title>",
		`id="event-filter"`,
		`id="outcome-filter"`,
		`id="days-filter"`,
		`id="username-filter"`,
		`value="` + authlog.EventLoginSuccess + `"`,
		`value="` + authlog.OutcomeFailure + `"`,
		"No authentication events found",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("empty page missing %q", needle)
		}
	}
}

func TestGetSecurityLog_RendersRowsNewestFirst(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	appendAuthEvent(t, f, authlog.Event{
		Event:     authlog.EventLoginSuccess,
		Outcome:   authlog.OutcomeSuccess,
		UserID:    "user-1",
		Username:  "alice",
		IP:        "192.0.2.1",
		UserAgent: "Mozilla/5.0 test",
		Detail:    "password",
	})
	appendAuthEvent(t, f, authlog.Event{
		Event:    authlog.EventLoginFailure,
		Outcome:  authlog.OutcomeFailure,
		Username: "bob",
		IP:       "192.0.2.2",
		Detail:   "invalid credentials",
	})

	rec := getSecurityLog(t, f, "/admin/security-log")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()

	for _, needle := range []string{
		"alice",
		"bob",
		"badge badge-green",
		"badge badge-red",
		"192.0.2.1",
		`title="Mozilla/5.0 test"`,
		"invalid credentials",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("body missing %q", needle)
		}
	}

	// Newest first: bob was inserted last.
	if bob, alice := strings.Index(body, "<td class=\"font-medium\">bob"), strings.Index(body, "<td class=\"font-medium\">alice"); bob < 0 || alice < 0 || bob > alice {
		t.Errorf("rows are not newest first: bob at %d, alice at %d", bob, alice)
	}
}

func TestGetSecurityLog_Filters(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	appendAuthEvent(t, f, authlog.Event{
		Event:    authlog.EventLoginSuccess,
		Outcome:  authlog.OutcomeSuccess,
		Username: "alice",
	})
	appendAuthEvent(t, f, authlog.Event{
		Event:    authlog.EventLoginFailure,
		Outcome:  authlog.OutcomeFailure,
		Username: "bob",
	})

	tests := []struct {
		name       string
		target     string
		want       string
		wantAbsent string
	}{
		{name: "event", target: "/admin/security-log?event=login.failure", want: "bob", wantAbsent: "alice"},
		{name: "outcome", target: "/admin/security-log?outcome=failure", want: "bob", wantAbsent: "alice"},
		{name: "username substring", target: "/admin/security-log?username=ali", want: "alice", wantAbsent: "bob"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := getSecurityLog(t, f, tc.target)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tc.want) {
				t.Errorf("body missing %q", tc.want)
			}
			if strings.Contains(body, tc.wantAbsent) {
				t.Errorf("body unexpectedly contains %q", tc.wantAbsent)
			}
		})
	}
}

func TestGetSecurityLog_MalformedFiltersDoNotError(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := getSecurityLog(t, f, "/admin/security-log?days=banana&page=-4&outcome=bogus&event=%3Cscript%3E&username=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert") {
		t.Error("username filter was not HTML-escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped username filter not echoed back into the input")
	}
	// days falls back to the default and the page to 1.
	if !strings.Contains(body, `<option value="30" selected>`) {
		t.Error("malformed days did not fall back to the 30-day option")
	}
}

func TestGetSecurityLog_OutOfRangePageIsClamped(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	appendAuthEvent(t, f, authlog.Event{Event: authlog.EventLoginSuccess, Outcome: authlog.OutcomeSuccess, Username: "alice"})

	rec := getSecurityLog(t, f, "/admin/security-log?page=999")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Page 1 of 1") {
		t.Errorf("out-of-range page was not clamped; body does not say Page 1 of 1")
	}
	if !strings.Contains(body, "alice") {
		t.Error("out-of-range page hid the only event")
	}
}

func TestGetSecurityLog_PaginationPreservesFilters(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// One page plus one row, all inside the window.
	for i := 0; i < 51; i++ {
		appendAuthEvent(t, f, authlog.Event{
			Event:     authlog.EventLoginFailure,
			Outcome:   authlog.OutcomeFailure,
			Username:  "bob",
			CreatedAt: time.Now().UTC().Add(-time.Duration(i) * time.Second),
		})
	}

	first := getSecurityLog(t, f, "/admin/security-log?event=login.failure&days=7")
	firstBody := first.Body.String()
	for _, needle := range []string{
		"Page 1 of 2",
		"Next",
		"event=login.failure",
		"days=7",
		"page=2",
	} {
		if !strings.Contains(firstBody, needle) {
			t.Errorf("page 1 missing %q", needle)
		}
	}
	if strings.Contains(firstBody, ">Previous<") {
		t.Error("page 1 should not offer Previous")
	}

	second := getSecurityLog(t, f, "/admin/security-log?event=login.failure&days=7&page=2")
	secondBody := second.Body.String()
	if !strings.Contains(secondBody, "Page 2 of 2") {
		t.Errorf("page 2 missing page indicator; got %q", secondBody)
	}
	if !strings.Contains(secondBody, ">Previous<") {
		t.Error("page 2 should offer Previous")
	}
	if strings.Contains(secondBody, ">Next<") {
		t.Error("page 2 should not offer Next")
	}
}

func TestGetSecurityLog_RequiresAdminSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	r := chi.NewRouter()
	r.Route("/admin", func(r chi.Router) {
		r.Use(admin.RequireAdmin(f.sessionSvc, f.cfg))
		f.handler.Routes(r)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/security-log", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want %q", loc, "/login")
	}
}
