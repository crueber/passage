package user_test

import (
	"context"
	"database/sql"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

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

// handlerFixture holds all wired dependencies for user handler tests.
type handlerFixture struct {
	db      *sql.DB
	handler *user.Handler
	userSvc *user.Service
	cfg     *config.Config
}

// newHandlerFixture builds a Handler wired to a real in-memory DB.
// It returns the handler and cfg so tests can inspect cookie names.
func newHandlerFixture(t *testing.T, allowRegistration bool) (*user.Handler, *config.Config) {
	t.Helper()
	f := newFullHandlerFixture(t, allowRegistration)
	return f.handler, f.cfg
}

// newFullHandlerFixture builds all dependencies and returns a fixture struct
// so tests can access the DB and service for setup and assertions.
func newFullHandlerFixture(t *testing.T, allowRegistration bool) *handlerFixture {
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
	sessionSvc := session.NewService(sessionStore, userStore, nil, cfg, slog.Default())

	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	h := user.NewHandler(userSvc, sessionSvc, noopSettings{}, noopSender{}, tmpl, cfg, logger)

	return &handlerFixture{
		db:      db,
		handler: h,
		userSvc: userSvc,
		cfg:     cfg,
	}
}

// withChiToken injects a chi route URL parameter "token" into the request context.
// Used when calling handler methods directly for routes that use chi.URLParam.
func withChiToken(r *http.Request, token string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("token", token)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
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
	sessionSvc := session.NewService(sessionStore, userStore, nil, cfg, slog.Default())
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
	})
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
	sessionSvc := session.NewService(sessionStore, userStore, nil, cfg, slog.Default())
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
	})
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

// ─── Group A: PostRegister error paths ───────────────────────────────────────

// TestHandler_PostRegister_DuplicateUsername verifies that registering with an
// already-taken username re-renders the form with an error and no session cookie.
func TestHandler_PostRegister_DuplicateUsername(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register the first user via the service.
	if _, err := f.userSvc.Register(context.Background(), "dupuser", "first@example.com", "password123"); err != nil {
		t.Fatalf("Register first user: %v", err)
	}

	// Attempt to register with the same username but a different email.
	form := url.Values{}
	form.Set("username", "dupuser")
	form.Set("email", "second@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostRegister(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostRegister duplicate username: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(strings.ToLower(body), "username") && !strings.Contains(strings.ToLower(body), "taken") {
		t.Errorf("PostRegister duplicate username: body does not mention username or taken; got:\n%s", body)
	}
	for _, c := range res.Cookies() {
		if c.Name == f.cfg.Session.CookieName && c.Value != "" {
			t.Errorf("PostRegister duplicate username: unexpected session cookie set")
		}
	}
}

// TestHandler_PostRegister_DuplicateEmail verifies that registering with an
// already-used email re-renders the form with an error and no session cookie.
func TestHandler_PostRegister_DuplicateEmail(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register the first user via the service.
	if _, err := f.userSvc.Register(context.Background(), "firstuser", "shared@example.com", "password123"); err != nil {
		t.Fatalf("Register first user: %v", err)
	}

	// Attempt to register with a different username but the same email.
	form := url.Values{}
	form.Set("username", "seconduser")
	form.Set("email", "shared@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostRegister(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostRegister duplicate email: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := strings.ToLower(rec.Body.String())
	if !strings.Contains(body, "email") && !strings.Contains(body, "account") {
		t.Errorf("PostRegister duplicate email: body does not mention email or account; got:\n%s", rec.Body.String())
	}
	for _, c := range res.Cookies() {
		if c.Name == f.cfg.Session.CookieName && c.Value != "" {
			t.Errorf("PostRegister duplicate email: unexpected session cookie set")
		}
	}
}

// TestHandler_PostRegister_ShortPassword verifies that a too-short password
// re-renders the form with an error and no session cookie.
func TestHandler_PostRegister_ShortPassword(t *testing.T) {
	t.Parallel()
	h, cfg := newHandlerFixture(t, true)

	form := url.Values{}
	form.Set("username", "validuser")
	form.Set("email", "valid@example.com")
	form.Set("password", "abc") // 3 characters — too short

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.PostRegister(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostRegister short password: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := strings.ToLower(rec.Body.String())
	if !strings.Contains(body, "password") {
		t.Errorf("PostRegister short password: body does not mention password; got:\n%s", rec.Body.String())
	}
	for _, c := range res.Cookies() {
		if c.Name == cfg.Session.CookieName && c.Value != "" {
			t.Errorf("PostRegister short password: unexpected session cookie set")
		}
	}
}

// TestHandler_PostRegister_MissingUsername verifies that an empty username
// re-renders the form with an error and no session cookie.
func TestHandler_PostRegister_MissingUsername(t *testing.T) {
	t.Parallel()
	h, cfg := newHandlerFixture(t, true)

	form := url.Values{}
	form.Set("username", "") // empty username
	form.Set("email", "someone@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.PostRegister(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostRegister missing username: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := strings.ToLower(rec.Body.String())
	if !strings.Contains(body, "username") && !strings.Contains(body, "required") {
		t.Errorf("PostRegister missing username: body does not mention username or required; got:\n%s", rec.Body.String())
	}
	for _, c := range res.Cookies() {
		if c.Name == cfg.Session.CookieName && c.Value != "" {
			t.Errorf("PostRegister missing username: unexpected session cookie set")
		}
	}
}

// ─── Group B: Password reset handler flow ─────────────────────────────────────

// TestHandler_GetResetRequest verifies that GET /reset returns 200 and a form.
func TestHandler_GetResetRequest(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, true)

	req := httptest.NewRequest(http.MethodGet, "/reset", nil)
	rec := httptest.NewRecorder()
	h.GetResetRequest(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("GetResetRequest: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<form") {
		t.Errorf("GetResetRequest: body does not contain <form; got:\n%s", body)
	}
}

// TestHandler_PostResetRequest_ValidEmail verifies that submitting a known email
// always returns 200 with a success/confirmation message (anti-enumeration).
func TestHandler_PostResetRequest_ValidEmail(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register a user first.
	if _, err := f.userSvc.Register(context.Background(), "resetuser", "reset@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	form := url.Values{}
	form.Set("email", "reset@example.com")

	req := httptest.NewRequest(http.MethodPost, "/reset", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostResetRequest(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostResetRequest valid email: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	// Should show a success/confirmation message, not an error.
	body := rec.Body.String()
	if strings.Contains(strings.ToLower(body), "flash-error") {
		t.Errorf("PostResetRequest valid email: body contains error flash; got:\n%s", body)
	}
	if !strings.Contains(strings.ToLower(body), "reset") {
		t.Errorf("PostResetRequest valid email: body does not mention reset; got:\n%s", body)
	}
}

// TestHandler_PostResetRequest_UnknownEmail verifies that submitting an unknown
// email still returns 200 (anti-enumeration — same response regardless).
func TestHandler_PostResetRequest_UnknownEmail(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, true)

	form := url.Values{}
	form.Set("email", "nobody@nowhere.example.com")

	req := httptest.NewRequest(http.MethodPost, "/reset", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.PostResetRequest(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostResetRequest unknown email: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	// Must not expose whether the email exists — no error flash.
	body := rec.Body.String()
	if strings.Contains(strings.ToLower(body), "flash-error") {
		t.Errorf("PostResetRequest unknown email: body contains error flash (enumeration risk); got:\n%s", body)
	}
}

// TestHandler_GetResetConfirm verifies that GET /reset/{token} returns 200 and
// a password form for a valid token.
func TestHandler_GetResetConfirm(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register a user and generate a real reset token.
	if _, err := f.userSvc.Register(context.Background(), "confirmuser", "confirm@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	token, err := f.userSvc.GeneratePasswordReset(context.Background(), "confirm@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordReset: %v", err)
	}
	if token == "" {
		t.Fatal("GeneratePasswordReset returned empty token")
	}

	req := httptest.NewRequest(http.MethodGet, "/reset/"+token, nil)
	req = withChiToken(req, token)
	rec := httptest.NewRecorder()
	f.handler.GetResetConfirm(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("GetResetConfirm: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<form") {
		t.Errorf("GetResetConfirm: body does not contain <form; got:\n%s", body)
	}
}

// TestHandler_PostResetConfirm_Success verifies that a valid token + matching
// passwords resets the password and redirects to /login.
func TestHandler_PostResetConfirm_Success(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register a user and generate a real reset token.
	if _, err := f.userSvc.Register(context.Background(), "resetok", "resetok@example.com", "oldpassword"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	token, err := f.userSvc.GeneratePasswordReset(context.Background(), "resetok@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordReset: %v", err)
	}

	form := url.Values{}
	form.Set("password", "newpassword1")
	form.Set("password_confirm", "newpassword1")

	req := httptest.NewRequest(http.MethodPost, "/reset/"+token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiToken(req, token)
	rec := httptest.NewRecorder()
	f.handler.PostResetConfirm(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostResetConfirm success: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("PostResetConfirm success: redirect %q does not contain /login", loc)
	}

	// Old password must no longer work.
	if _, err := f.userSvc.Authenticate(context.Background(), "resetok", "oldpassword"); err == nil {
		t.Errorf("PostResetConfirm success: old password still authenticates — password was not changed")
	}

	// New password must work.
	if _, err := f.userSvc.Authenticate(context.Background(), "resetok", "newpassword1"); err != nil {
		t.Errorf("PostResetConfirm success: new password does not authenticate: %v", err)
	}
}

// TestHandler_PostResetConfirm_PasswordMismatch verifies that mismatched
// passwords re-render the form with an error (status 200).
func TestHandler_PostResetConfirm_PasswordMismatch(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register a user and generate a real reset token.
	if _, err := f.userSvc.Register(context.Background(), "mismatchuser", "mismatch@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	token, err := f.userSvc.GeneratePasswordReset(context.Background(), "mismatch@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordReset: %v", err)
	}

	form := url.Values{}
	form.Set("password", "newpassword1")
	form.Set("password_confirm", "differentpassword")

	req := httptest.NewRequest(http.MethodPost, "/reset/"+token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiToken(req, token)
	rec := httptest.NewRecorder()
	f.handler.PostResetConfirm(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostResetConfirm mismatch: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := strings.ToLower(rec.Body.String())
	if !strings.Contains(body, "match") && !strings.Contains(body, "password") {
		t.Errorf("PostResetConfirm mismatch: body does not mention match or password; got:\n%s", rec.Body.String())
	}
}

// TestHandler_PostResetConfirm_ExpiredToken verifies that an expired token
// re-renders the form with an appropriate error.
func TestHandler_PostResetConfirm_ExpiredToken(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register a user to get a valid user ID for the token row.
	if _, err := f.userSvc.Register(context.Background(), "expireduser", "expired@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Insert a reset token with an expires_at in the past directly via raw SQL.
	expiredToken := "expiredtokenvalue0000000000000000"
	past := time.Now().UTC().Add(-2 * time.Hour)
	createdAt := time.Now().UTC().Add(-3 * time.Hour)
	_, err := f.db.ExecContext(context.Background(),
		`INSERT INTO password_reset_tokens (token, user_id, expires_at, created_at)
		 SELECT ?, id, ?, ? FROM users WHERE username = ?`,
		expiredToken, past, createdAt, "expireduser",
	)
	if err != nil {
		t.Fatalf("insert expired token: %v", err)
	}

	form := url.Values{}
	form.Set("password", "newpassword1")
	form.Set("password_confirm", "newpassword1")

	req := httptest.NewRequest(http.MethodPost, "/reset/"+expiredToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiToken(req, expiredToken)
	rec := httptest.NewRecorder()
	f.handler.PostResetConfirm(rec, req)

	res := rec.Result()
	// Handler renders the form with an error on expired token (status 200).
	if res.StatusCode != http.StatusOK {
		t.Errorf("PostResetConfirm expired: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := strings.ToLower(rec.Body.String())
	if !strings.Contains(body, "expired") && !strings.Contains(body, "reset") {
		t.Errorf("PostResetConfirm expired: body does not mention expired or reset; got:\n%s", rec.Body.String())
	}
}

// ─── Group C: passage_rd cookie flow ─────────────────────────────────────────

// TestHandler_PostLogin_PassageRdCookie verifies that a valid login with a
// passage_rd cookie redirects to the cookie's path and clears the cookie.
func TestHandler_PostLogin_PassageRdCookie(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register a user.
	if _, err := f.userSvc.Register(context.Background(), "rdcookieuser", "rdcookie@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	form := url.Values{}
	form.Set("username", "rdcookieuser")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Set the passage_rd cookie to a local path.
	req.AddCookie(&http.Cookie{Name: "passage_rd", Value: "/target/path"})
	rec := httptest.NewRecorder()
	f.handler.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostLogin passage_rd: got status %d, want %d", res.StatusCode, http.StatusFound)
	}

	// Must redirect to the passage_rd cookie value.
	loc := res.Header.Get("Location")
	if loc != "/target/path" {
		t.Errorf("PostLogin passage_rd: got redirect to %q, want %q", loc, "/target/path")
	}

	// The passage_rd cookie must be cleared in the response.
	var rdCookieCleared bool
	for _, c := range res.Cookies() {
		if c.Name == "passage_rd" {
			// Cleared means MaxAge == -1 or Value is empty with past Expires.
			if c.MaxAge == -1 || c.Value == "" {
				rdCookieCleared = true
			}
		}
	}
	if !rdCookieCleared {
		t.Errorf("PostLogin passage_rd: passage_rd cookie was not cleared in the response")
	}
}

// ─── Group D: Admin auto-redirect ─────────────────────────────────────────────

// TestHandler_PostLogin_AdminRedirect verifies that an admin user with no
// passage_rd cookie and no rd form field is redirected to /admin.
func TestHandler_PostLogin_AdminRedirect(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Create an admin user directly via CreateAdmin.
	if _, err := f.userSvc.CreateAdmin(context.Background(), "adminuser", "admin@example.com", "password123"); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	form := url.Values{}
	form.Set("username", "adminuser")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostLogin admin redirect: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if loc != "/admin" {
		t.Errorf("PostLogin admin redirect: got redirect to %q, want %q", loc, "/admin")
	}
}

// TestHandler_PostLogin_NonAdminRedirect verifies that a non-admin user with no
// passage_rd cookie and no rd form field is redirected to / (not /admin).
func TestHandler_PostLogin_NonAdminRedirect(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Register a regular (non-admin) user.
	if _, err := f.userSvc.Register(context.Background(), "regularuser", "regular@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	form := url.Values{}
	form.Set("username", "regularuser")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostLogin non-admin redirect: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if loc != "/" {
		t.Errorf("PostLogin non-admin redirect: got redirect to %q, want %q", loc, "/")
	}
}

// TestHandler_PostLogin_AdminWithRdField verifies that an admin user who has a
// valid rd form field is sent to that destination (not overridden to /admin).
func TestHandler_PostLogin_AdminWithRdField(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Create an admin user.
	if _, err := f.userSvc.CreateAdmin(context.Background(), "adminrd", "adminrd@example.com", "password123"); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	form := url.Values{}
	form.Set("username", "adminrd")
	form.Set("password", "password123")
	form.Set("rd", "/dashboard")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostLogin admin with rd: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if loc != "/dashboard" {
		t.Errorf("PostLogin admin with rd: got redirect to %q, want %q", loc, "/dashboard")
	}
}

// TestHandler_PostLogin_AdminWithPassageRdCookie verifies that an admin user
// who has a passage_rd cookie is still redirected to the cookie's path — the
// cookie takes priority over the /admin default.
func TestHandler_PostLogin_AdminWithPassageRdCookie(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	// Create an admin user.
	if _, err := f.userSvc.CreateAdmin(context.Background(), "admincookie", "admincookie@example.com", "password123"); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	form := url.Values{}
	form.Set("username", "admincookie")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Set the passage_rd cookie to simulate a forward-auth flow redirect.
	req.AddCookie(&http.Cookie{Name: "passage_rd", Value: "/protected/app"})
	rec := httptest.NewRecorder()
	f.handler.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("PostLogin admin with passage_rd: got status %d, want %d", res.StatusCode, http.StatusFound)
	}

	// Must redirect to the passage_rd path, not /admin.
	loc := res.Header.Get("Location")
	if loc != "/protected/app" {
		t.Errorf("PostLogin admin with passage_rd: got redirect to %q, want %q", loc, "/protected/app")
	}

	// The passage_rd cookie must be cleared.
	var rdCookieCleared bool
	for _, c := range res.Cookies() {
		if c.Name == "passage_rd" {
			if c.MaxAge == -1 || c.Value == "" {
				rdCookieCleared = true
			}
		}
	}
	if !rdCookieCleared {
		t.Errorf("PostLogin admin with passage_rd: passage_rd cookie was not cleared in the response")
	}
}
