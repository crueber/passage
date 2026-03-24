package user_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// noopSender satisfies the email.Sender interface with a no-op implementation.
type noopSender struct{}

func (noopSender) SendPasswordReset(_ context.Context, _, _, _ string) error { return nil }

// noopSettings satisfies the settingsReader interface with a no-op implementation.
// Always returns an error so the handler falls back to the static config.
type noopSettings struct{}

func (noopSettings) Get(_ context.Context, _ string) (string, error) {
	return "", errors.New("not found")
}

// newHandlerFixture builds a Handler wired to a real in-memory DB.
// It returns the handler and cfg so tests can inspect cookie names.
func newHandlerFixture(t *testing.T, allowRegistration bool) (*user.Handler, *config.Config) {
	t.Helper()

	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)

	cfg := &config.Config{
		Auth: config.AuthConfig{
			AllowRegistration: allowRegistration,
			BcryptCost:        10,
		},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
	}

	userSvc := user.NewService(userStore, userStore, cfg)

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, cfg, slog.Default())

	tmpl, err := web.Parse(web.TemplateFS)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	h := user.NewHandler(userSvc, sessionSvc, noopSettings{}, noopSender{}, tmpl, cfg, logger)
	return h, cfg
}

// TestHandler_GetLogin verifies that GET /login returns 200 and contains a form.
func TestHandler_GetLogin(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, true)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.GetLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("GetLogin: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<form") {
		t.Errorf("GetLogin: response body does not contain <form>; got:\n%s", body)
	}
}

// TestHandler_PostLogin_InvalidCredentials verifies that POSTing wrong
// credentials returns 200 (re-renders the form) and does not redirect.
func TestHandler_PostLogin_InvalidCredentials(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, true)

	form := url.Values{}
	form.Set("username", "nobody")
	form.Set("password", "wrongpassword")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostLogin invalid creds: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	// Must not redirect.
	if loc := res.Header.Get("Location"); loc != "" {
		t.Errorf("PostLogin invalid creds: unexpected redirect to %q", loc)
	}
}

// TestHandler_PostLogin_Success verifies that a valid login sets the session
// cookie and redirects (302).
func TestHandler_PostLogin_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := &config.Config{
		Auth:    config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{DurationHours: 24, CookieName: "passage_session"},
	}
	userSvc := user.NewService(userStore, userStore, cfg)

	// Register a user first.
	if _, err := userSvc.Register(context.Background(), "loginuser", "login@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, cfg, slog.Default())
	tmpl, err := web.Parse(web.TemplateFS)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	h := user.NewHandler(userSvc, sessionSvc, noopSettings{}, noopSender{}, tmpl, cfg, logger)

	form := url.Values{}
	form.Set("username", "loginuser")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostLogin success: got status %d, want %d", res.StatusCode, http.StatusFound)
	}

	// Must set the session cookie.
	var found bool
	for _, c := range res.Cookies() {
		if c.Name == cfg.Session.CookieName && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("PostLogin success: session cookie %q not set", cfg.Session.CookieName)
	}
}

// TestHandler_PostLogin_OpenRedirect verifies that a redirect to an external
// host is rejected and the destination falls back to "/".
func TestHandler_PostLogin_OpenRedirect(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := &config.Config{
		Auth:    config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{DurationHours: 24, CookieName: "passage_session"},
	}
	userSvc := user.NewService(userStore, userStore, cfg)
	if _, err := userSvc.Register(context.Background(), "rduser", "rd@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, cfg, slog.Default())
	tmpl, err := web.Parse(web.TemplateFS)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	h := user.NewHandler(userSvc, sessionSvc, noopSettings{}, noopSender{}, tmpl, cfg, logger)

	form := url.Values{}
	form.Set("username", "rduser")
	form.Set("password", "password123")
	form.Set("rd", "https://evil.com/steal")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostLogin open-redirect: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if strings.HasPrefix(loc, "https://evil.com") || strings.HasPrefix(loc, "http://evil.com") {
		t.Errorf("PostLogin open-redirect: redirected to external URL %q — open redirect!", loc)
	}
	if loc != "/" {
		t.Errorf("PostLogin open-redirect: got redirect to %q, want %q", loc, "/")
	}
}

// TestHandler_GetLogout verifies that GET /logout clears the cookie and
// redirects to /login.
func TestHandler_GetLogout(t *testing.T) {
	t.Parallel()
	h, cfg := newHandlerFixture(t, true)

	// Provide a fake session cookie so the handler attempts a revoke.
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: "fake-session-token"})
	rec := httptest.NewRecorder()
	h.GetLogout(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("GetLogout: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if loc != "/login" {
		t.Errorf("GetLogout: got redirect to %q, want %q", loc, "/login")
	}

	// The session cookie must be cleared (MaxAge == -1).
	for _, c := range res.Cookies() {
		if c.Name == cfg.Session.CookieName {
			if c.MaxAge != -1 {
				t.Errorf("GetLogout: session cookie not cleared: Value=%q MaxAge=%d", c.Value, c.MaxAge)
			}
		}
	}
}

// TestHandler_GetRegister_Disabled verifies that GET /register redirects when
// registration is disabled.
func TestHandler_GetRegister_Disabled(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, false /* allowRegistration=false */)

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	rec := httptest.NewRecorder()
	h.GetRegister(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("GetRegister disabled: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "registration-disabled") {
		t.Errorf("GetRegister disabled: redirect %q does not mention registration-disabled", loc)
	}
}

// TestHandler_PostRegister_Success verifies that a valid POST /register creates
// a user and sets a session cookie (auto-login after registration).
func TestHandler_PostRegister_Success(t *testing.T) {
	t.Parallel()
	h, cfg := newHandlerFixture(t, true)

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("email", "newuser@example.com")
	form.Set("password", "securepassword")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.PostRegister(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostRegister success: got status %d, want %d", res.StatusCode, http.StatusFound)
	}

	// Must set the session cookie (auto-login after registration).
	var found bool
	for _, c := range res.Cookies() {
		if c.Name == cfg.Session.CookieName && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("PostRegister success: session cookie %q not set", cfg.Session.CookieName)
	}
}
