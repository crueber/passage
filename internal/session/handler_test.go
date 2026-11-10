package session_test

import (
	"context"
	"database/sql"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/theme"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// sessionsFixture wires the user-facing sessions handler to a real in-memory DB.
type sessionsFixture struct {
	db      *sql.DB
	users   *user.Service
	svc     *session.Service
	handler *session.Handler
	cfg     *config.Config
	user    *user.User
}

func newSessionsFixture(t *testing.T) *sessionsFixture {
	t.Helper()

	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := &config.Config{
		Auth: config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
	}
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	store := session.NewStore(db)
	svc := session.NewService(store, userStore, nil, nil, cfg, slog.Default())

	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(token string) template.HTML {
			// Mirrors cmd/passage: the token is base64url, so HTML is safe.
			return template.HTML(`<input type="hidden" name="` + csrf.FieldName + `" value="` + token + `">`)
		},
		"theme": func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	u, err := userSvc.Register(context.Background(), "sess_user", "sess@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	return &sessionsFixture{
		db:      db,
		users:   userSvc,
		svc:     svc,
		handler: session.NewHandler(svc, tmpl, cfg, logger),
		cfg:     cfg,
		user:    u,
	}
}

// newSession creates a session for the fixture user and returns it.
func (f *sessionsFixture) newSession(t *testing.T, ip, ua string) *session.Session {
	t.Helper()
	sess, err := f.svc.NewSession(context.Background(), f.user.ID, nil, ip, ua)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return sess
}

// request builds a request carrying the given authenticated user and current
// session in its context, as RequireSession would. When a session is supplied
// its bearer token is also attached as the session cookie, mirroring the
// browser.
func authenticatedRequest(method, target string, body *strings.Reader, u *user.User, cur *session.Session) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	ctx := session.WithUser(req.Context(), u)
	if cur != nil {
		ctx = session.WithSession(ctx, cur)
		req.AddCookie(&http.Cookie{Name: "passage_session", Value: cur.ID})
	}
	return req.WithContext(ctx)
}

func TestGetSessions_ListsOwnSessionsOnly(t *testing.T) {
	t.Parallel()
	f := newSessionsFixture(t)

	current := f.newSession(t, "203.0.113.5", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	other := f.newSession(t, "198.51.100.7", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")

	// A session belonging to somebody else must never appear.
	otherUser, err := f.users.Register(context.Background(), "other_user", "other@example.com", "password123")
	if err != nil {
		t.Fatalf("Register other user: %v", err)
	}
	if _, err := f.svc.NewSession(context.Background(), otherUser.ID, nil, "10.9.9.9", "OtherAgent/9.9"); err != nil {
		t.Fatalf("NewSession other user: %v", err)
	}

	// An absolutely expired session of this user must be filtered out: the page
	// must never offer a revoke button for a session validation already rejects.
	now := time.Now().UTC()
	if _, err := f.db.ExecContext(context.Background(),
		`INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at, last_used_at)
		 VALUES ('expired-token', 'expired-public', ?, NULL, '192.0.2.99', 'ExpiredAgent/1', ?, ?, ?)`,
		f.user.ID, now.Add(-time.Hour), now.Add(-2*time.Hour), now.Add(-2*time.Hour),
	); err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	req := authenticatedRequest(http.MethodGet, "/sessions", nil, f.user, current)
	rec := httptest.NewRecorder()
	f.handler.GetSessions(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GetSessions: got status %d, want 200", res.StatusCode)
	}
	body := rec.Body.String()

	for _, want := range []string{
		"Sessions",
		"Chrome on Windows",
		"Firefox on Linux",
		"203.0.113.5",
		"198.51.100.7",
		"This device",
		"Sign out everywhere",
		current.PublicID,
		other.PublicID,
		`name="` + csrf.FieldName + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}

	for _, unwanted := range []string{
		"10.9.9.9",       // another user's IP
		"192.0.2.99",     // an expired session of this user
		"expired-public", // never rendered
		current.ID,       // the bearer token must never reach the page
		other.ID,
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("body unexpectedly contains %q", unwanted)
		}
	}
}

func TestGetSessions_EmptyState(t *testing.T) {
	t.Parallel()
	f := newSessionsFixture(t)

	req := authenticatedRequest(http.MethodGet, "/sessions", nil, f.user, nil)
	rec := httptest.NewRecorder()
	f.handler.GetSessions(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "No active sessions") {
		t.Error("empty page missing empty state")
	}
	if strings.Contains(body, "Sign out everywhere") {
		t.Error("empty page should not offer sign-out-everywhere")
	}
}

func TestGetSessions_Unauthenticated(t *testing.T) {
	t.Parallel()
	f := newSessionsFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	rec := httptest.NewRecorder()
	f.handler.GetSessions(rec, req)

	if res := rec.Result(); res.StatusCode != http.StatusFound {
		t.Fatalf("GetSessions without user: got status %d, want 302", res.StatusCode)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("redirect target = %q, want /login", loc)
	}
}

func TestPostRevokeSession_RevokesOwned(t *testing.T) {
	t.Parallel()
	f := newSessionsFixture(t)

	current := f.newSession(t, "203.0.113.5", "Agent/1")
	victim := f.newSession(t, "198.51.100.7", "Agent/2")

	form := url.Values{"public_id": {victim.PublicID}}
	req := authenticatedRequest(http.MethodPost, "/sessions/revoke", strings.NewReader(form.Encode()), f.user, current)
	rec := httptest.NewRecorder()
	f.handler.PostRevokeSession(rec, req)

	if res := rec.Result(); res.StatusCode != http.StatusFound {
		t.Fatalf("PostRevokeSession: got status %d, want 302", res.StatusCode)
	}
	if loc := rec.Header().Get("Location"); loc != "/sessions?flash=revoked" {
		t.Errorf("redirect target = %q, want /sessions?flash=revoked", loc)
	}

	// The revoked session is gone; the current one survives.
	if _, _, err := f.svc.ValidateSession(context.Background(), victim.ID); err == nil {
		t.Error("revoked session still validates")
	}
	if _, _, err := f.svc.ValidateSession(context.Background(), current.ID); err != nil {
		t.Errorf("current session was revoked too: %v", err)
	}
}

func TestPostRevokeSession_RejectsUnowned(t *testing.T) {
	t.Parallel()
	f := newSessionsFixture(t)

	current := f.newSession(t, "203.0.113.5", "Agent/1")

	otherUser, err := f.users.Register(context.Background(), "victim_user", "victim@example.com", "password123")
	if err != nil {
		t.Fatalf("Register other user: %v", err)
	}
	victim, err := f.svc.NewSession(context.Background(), otherUser.ID, nil, "10.1.2.3", "VictimAgent/1")
	if err != nil {
		t.Fatalf("NewSession victim: %v", err)
	}

	form := url.Values{"public_id": {victim.PublicID}}
	req := authenticatedRequest(http.MethodPost, "/sessions/revoke", strings.NewReader(form.Encode()), f.user, current)
	rec := httptest.NewRecorder()
	f.handler.PostRevokeSession(rec, req)

	if loc := rec.Header().Get("Location"); loc != "/sessions?flash=error" {
		t.Errorf("redirect target = %q, want /sessions?flash=error", loc)
	}
	if _, _, err := f.svc.ValidateSession(context.Background(), victim.ID); err != nil {
		t.Errorf("another user's session was revoked: %v", err)
	}
}

func TestPostRevokeSession_CurrentClearsCookie(t *testing.T) {
	t.Parallel()
	f := newSessionsFixture(t)

	current := f.newSession(t, "203.0.113.5", "Agent/1")

	form := url.Values{"public_id": {current.PublicID}}
	req := authenticatedRequest(http.MethodPost, "/sessions/revoke", strings.NewReader(form.Encode()), f.user, current)
	rec := httptest.NewRecorder()
	f.handler.PostRevokeSession(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("PostRevokeSession: got status %d, want 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/login" {
		t.Errorf("redirect target = %q, want /login", loc)
	}

	cookie := findCookie(t, res.Cookies(), f.cfg.Session.EffectiveCookieName())
	if cookie.Value != "" {
		t.Errorf("cookie value = %q, want empty", cookie.Value)
	}
	if cookie.MaxAge >= 0 {
		t.Errorf("cookie MaxAge = %d, want negative", cookie.MaxAge)
	}
	if !cookie.HttpOnly {
		t.Error("cleared cookie is not HttpOnly")
	}

	if _, _, err := f.svc.ValidateSession(context.Background(), current.ID); err == nil {
		t.Error("current session still validates after revoke")
	}
}

func TestPostRevokeAllSessions(t *testing.T) {
	t.Parallel()
	f := newSessionsFixture(t)

	current := f.newSession(t, "203.0.113.5", "Agent/1")
	if _, err := f.svc.NewSession(context.Background(), f.user.ID, nil, "198.51.100.7", "Agent/2"); err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	otherUser, err := f.users.Register(context.Background(), "bystander", "bystander@example.com", "password123")
	if err != nil {
		t.Fatalf("Register other user: %v", err)
	}
	bystander, err := f.svc.NewSession(context.Background(), otherUser.ID, nil, "10.1.2.3", "Agent/3")
	if err != nil {
		t.Fatalf("NewSession bystander: %v", err)
	}

	req := authenticatedRequest(http.MethodPost, "/sessions/revoke-all", nil, f.user, current)
	rec := httptest.NewRecorder()
	f.handler.PostRevokeAllSessions(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("PostRevokeAllSessions: got status %d, want 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/login" {
		t.Errorf("redirect target = %q, want /login", loc)
	}
	if cookie := findCookie(t, res.Cookies(), f.cfg.Session.EffectiveCookieName()); cookie.Value != "" {
		t.Errorf("cookie value = %q, want empty", cookie.Value)
	}

	mine, err := f.svc.ListByUser(context.Background(), f.user.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(mine) != 0 {
		t.Errorf("got %d sessions after revoke-all, want 0", len(mine))
	}

	theirs, err := f.svc.ListByUser(context.Background(), otherUser.ID)
	if err != nil {
		t.Fatalf("ListByUser other: %v", err)
	}
	if len(theirs) != 1 || theirs[0].ID != bystander.ID {
		t.Errorf("another user's sessions were touched: got %d", len(theirs))
	}
}

// TestPostRevokeSession_MissingPublicID verifies an empty form field is a
// redirect with an error flash, not a panic or a 500.
func TestPostRevokeSession_MissingPublicID(t *testing.T) {
	t.Parallel()
	f := newSessionsFixture(t)
	current := f.newSession(t, "203.0.113.5", "Agent/1")

	req := authenticatedRequest(http.MethodPost, "/sessions/revoke", strings.NewReader(""), f.user, current)
	rec := httptest.NewRecorder()
	f.handler.PostRevokeSession(rec, req)

	if loc := rec.Header().Get("Location"); loc != "/sessions?flash=error" {
		t.Errorf("redirect target = %q, want /sessions?flash=error", loc)
	}
}

// findCookie returns the named cookie from a response, failing the test if it is
// absent or duplicated.
func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name != name {
			continue
		}
		if found != nil {
			t.Fatalf("duplicate %q cookie in response", name)
		}
		found = c
	}
	if found == nil {
		t.Fatalf("response did not set %q", name)
	}
	return found
}
