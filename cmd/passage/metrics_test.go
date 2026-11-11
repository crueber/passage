package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/metrics"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// testLogger discards log output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestNewServerMetrics_ExposesMetricSet builds the real metric set on a real
// in-memory database and scrapes it, which pins the metric names, help text,
// types, labels, and gauge values in one place.
func TestNewServerMetrics_ExposesMetricSet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := testutil.NewTestDB(t)

	userStore := user.NewStore(database)
	appStore := app.NewStore(database)
	sessionStore := session.NewStore(database)

	// Two users, one app, one live session, and one session that has expired.
	for _, username := range []string{"alice", "bob"} {
		if err := userStore.Create(ctx, &user.User{
			Username: username,
			Email:    username + "@example.com",
			IsActive: true,
		}); err != nil {
			t.Fatalf("create user %s: %v", username, err)
		}
	}
	var firstUser struct{ ID string }
	if err := database.QueryRowContext(ctx, `SELECT id FROM users ORDER BY username LIMIT 1`).Scan(&firstUser.ID); err != nil {
		t.Fatalf("read user id: %v", err)
	}

	if err := appStore.Create(ctx, &app.App{Slug: "nextcloud", Name: "Nextcloud", IsActive: true}); err != nil {
		t.Fatalf("create app: %v", err)
	}

	now := time.Now().UTC()
	if err := sessionStore.Create(ctx, &session.Session{
		ID:        "live-session",
		UserID:    firstUser.ID,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create live session: %v", err)
	}
	if err := sessionStore.Create(ctx, &session.Session{
		ID:        "expired-session",
		UserID:    firstUser.ID,
		ExpiresAt: now.Add(-time.Hour),
		CreatedAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("create expired session: %v", err)
	}

	started := time.Unix(1700000000, 0)
	m := newServerMetrics(testLogger(), "1.2.3-test", started, userStore, appStore, sessionStore)

	// Exercise the counters the request and sign-in paths increment.
	m.authEvents.Inc(authlog.EventLoginSuccess, authlog.OutcomeSuccess)
	m.authEvents.Inc(authlog.EventLoginFailure, authlog.OutcomeFailure)
	m.authEvents.Inc(authlog.EventLoginFailure, authlog.OutcomeFailure)
	m.SessionCreated()
	m.SessionRevoked()

	var body strings.Builder
	if err := m.reg.WriteText(ctx, &body); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	got := body.String()

	want := []string{
		"# TYPE passage_auth_events_total counter",
		`passage_auth_events_total{event="login.failure",outcome="failure"} 2`,
		`passage_auth_events_total{event="login.success",outcome="success"} 1`,
		"# TYPE passage_sessions_created_total counter",
		"passage_sessions_created_total 1",
		"# TYPE passage_sessions_revoked_total counter",
		"passage_sessions_revoked_total 1",
		"# TYPE passage_users gauge",
		"passage_users 2",
		"# TYPE passage_apps gauge",
		"passage_apps 1",
		"# TYPE passage_active_sessions gauge",
		"passage_active_sessions 1",
		"# TYPE passage_process_start_time_seconds gauge",
		"passage_process_start_time_seconds 1700000000",
		`# TYPE passage_build_info gauge`,
		`passage_build_info{version="1.2.3-test"} 1`,
	}
	for _, line := range want {
		if !strings.Contains(got, line) {
			t.Errorf("exposition is missing %q:\n%s", line, got)
		}
	}
}

// TestMetricsHandler_Integration scrapes through the HTTP middleware: the
// scrape itself must be counted like any other request, and every gauge must
// be present in the response.
func TestMetricsHandler_Integration(t *testing.T) {
	t.Parallel()

	database := testutil.NewTestDB(t)

	m := newServerMetrics(testLogger(), "dev", time.Now(),
		user.NewStore(database), app.NewStore(database), session.NewStore(database))

	handler := metrics.HTTPMiddleware(m.requests)(m.reg.Handler(metrics.HandlerOptions{
		Enabled: true,
		Token:   "scrape-token",
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer scrape-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}

	body := rec.Body.String()
	for _, line := range []string{
		"passage_users 0",
		"passage_apps 0",
		"passage_active_sessions 0",
	} {
		if !strings.Contains(body, line) {
			t.Errorf("scrape is missing %q:\n%s", line, body)
		}
	}

	// A request is counted when it finishes, so it appears in the *next*
	// scrape: the first scrape's own request shows up in the second response.
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, req)
	if want := `passage_http_requests_total{method="GET",status="200"} 1`; !strings.Contains(second.Body.String(), want) {
		t.Errorf("second scrape is missing %q:\n%s", want, second.Body.String())
	}
}

// TestAuthEventCounter verifies the recorder sink counts an event and still
// forwards it to the webhook sink behind it.
func TestAuthEventCounter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		withNext  bool
		event     authlog.Event
		wantEvent string
	}{
		{
			name:      "counted without a webhook",
			event:     authlog.Event{Event: authlog.EventLogout, Outcome: authlog.OutcomeSuccess},
			wantEvent: authlog.EventLogout,
		},
		{
			name:      "counted and forwarded",
			withNext:  true,
			event:     authlog.Event{Event: authlog.EventLoginFailure, Outcome: authlog.OutcomeFailure},
			wantEvent: authlog.EventLoginFailure,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reg := metrics.New(testLogger())
			counter := reg.Counter("passage_auth_events_total", "Events.", "event", "outcome")

			var sink *recordingNotifier
			var next authlog.Notifier
			if tc.withNext {
				sink = &recordingNotifier{}
				next = sink
			}

			authEventCounter{counter: counter, next: next}.Notify(tc.event)

			var body strings.Builder
			if err := reg.WriteText(context.Background(), &body); err != nil {
				t.Fatalf("WriteText: %v", err)
			}
			want := `passage_auth_events_total{event="` + tc.wantEvent + `",outcome="` + tc.event.Outcome + `"} 1`
			if !strings.Contains(body.String(), want) {
				t.Errorf("exposition is missing %q:\n%s", want, body.String())
			}

			if tc.withNext {
				if len(sink.events) != 1 || sink.events[0].Event != tc.wantEvent {
					t.Errorf("next sink got %+v, want one %q event", sink.events, tc.wantEvent)
				}
			}
		})
	}
}

// recordingNotifier captures events forwarded by the metrics sink.
type recordingNotifier struct {
	events []authlog.Event
}

func (r *recordingNotifier) Notify(e authlog.Event) {
	r.events = append(r.events, e)
}
