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

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/email"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/theme"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// noopSender satisfies the email.Sender interface with a no-op implementation.
type noopSender struct{}

func (noopSender) SendPasswordReset(_ context.Context, _, _, _ string) error { return nil }
func (noopSender) SendMagicLink(_ context.Context, _, _, _ string) error     { return nil }
func (noopSender) SendVerifyEmail(_ context.Context, _, _, _ string) error   { return nil }

// noopSettings satisfies the settingsReader interface with a no-op implementation.
// Always returns an error so the handler falls back to the static config.
type noopSettings struct{}

func (noopSettings) Get(_ context.Context, _ string) (string, error) {
	return "", errors.New("not found")
}

// fixtureSettings is a settingsReader backed by a map. A missing key returns an
// error, so handlers fall back to their config default exactly as they do in
// production when a setting has never been saved.
type fixtureSettings struct{ values map[string]string }

func (s *fixtureSettings) Get(_ context.Context, key string) (string, error) {
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}

// handlerFixture holds all wired dependencies for user handler tests.
type handlerFixture struct {
	db            *sql.DB
	handler       *user.Handler
	userSvc       *user.Service
	userStore     *user.SQLiteStore
	appSvc        *app.Service
	sessionSvc    *session.Service
	mfaSvc        *mfa.Service
	settings      *fixtureSettings
	cfg           *config.Config
	mailer        email.Sender
	authStore     *authlog.Store
	throttleStore *ratelimit.AccountStore
	throttle      *ratelimit.AccountService
	clock         *testClock
}

// testClock is a manually advanced clock so throttle tests never sleep.
type testClock struct {
	t time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time { return c.t }

func (c *testClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

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
	return newFullHandlerFixtureWith(t, allowRegistration, nil, noopSender{})
}

// newFullHandlerFixtureWith is newFullHandlerFixture with hooks to adjust the
// config (SMTP, base URL) and the mailer before the handler is built.
func newFullHandlerFixtureWith(t *testing.T, allowRegistration bool, mutate func(*config.Config), mailer email.Sender) *handlerFixture {
	return newFullHandlerFixtureAll(t, allowRegistration, 5, 15, mutate, mailer)
}

// newFullHandlerFixtureWithThrottle is newFullHandlerFixtureWithThrottle with
// explicit per-account throttle settings. Zero for either value disables
// throttling.
func newFullHandlerFixtureWithThrottle(t *testing.T, allowRegistration bool, maxFailures, lockoutMinutes int) *handlerFixture {
	return newFullHandlerFixtureAll(t, allowRegistration, maxFailures, lockoutMinutes, nil, noopSender{})
}

// newFullHandlerFixtureAll builds the full dependency graph.
func newFullHandlerFixtureAll(t *testing.T, allowRegistration bool, maxFailures, lockoutMinutes int, mutate func(*config.Config), mailer email.Sender) *handlerFixture {
	t.Helper()
	t.Helper()

	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)

	cfg := &config.Config{
		Auth: config.AuthConfig{
			AllowRegistration: allowRegistration,
			BcryptCost:        10,
			MaxLoginFailures:  maxFailures,
			LockoutMinutes:    lockoutMinutes,
		},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
	}
	if mutate != nil {
		mutate(cfg)
	}

	userSvc := user.NewService(userStore, userStore, nil, cfg)

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())

	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	appStore := app.NewStore(db)
	appSvc := app.NewService(appStore, appStore, logger)
	authStore := authlog.NewStore(db)
	authRecorder := authlog.NewRecorder(authStore, nil, logger)
	clock := newTestClock()
	throttleStore := ratelimit.NewAccountStore(db)
	throttle := ratelimit.NewAccountService(throttleStore, ratelimit.AccountConfig{
		MaxFailures: maxFailures,
		Lockout:     time.Duration(lockoutMinutes) * time.Minute,
	}, clock.Now)
	mfaSvc := mfa.NewService(mfa.NewStore(db, nil), "Passage", clock.Now)
	settings := &fixtureSettings{values: map[string]string{}}
	h := user.NewHandler(userSvc, mfaSvc, appSvc, sessionSvc, settings, mailer, session.UserFromContext, authRecorder, throttle, tmpl, cfg, logger)

	return &handlerFixture{
		db:            db,
		handler:       h,
		userSvc:       userSvc,
		userStore:     userStore,
		appSvc:        appSvc,
		sessionSvc:    sessionSvc,
		mfaSvc:        mfaSvc,
		settings:      settings,
		cfg:           cfg,
		mailer:        mailer,
		authStore:     authStore,
		throttleStore: throttleStore,
		throttle:      throttle,
		clock:         clock,
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
	userSvc := user.NewService(userStore, userStore, nil, cfg)

	// Register a user first.
	if _, err := userSvc.Register(context.Background(), "loginuser", "login@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	appStore := app.NewStore(db)
	h := user.NewHandler(userSvc, nil, app.NewService(appStore, appStore, logger), sessionSvc, noopSettings{}, noopSender{}, session.UserFromContext, nil, nil, tmpl, cfg, logger)

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
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	if _, err := userSvc.Register(context.Background(), "rduser", "rd@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	appStore := app.NewStore(db)
	h := user.NewHandler(userSvc, nil, app.NewService(appStore, appStore, logger), sessionSvc, noopSettings{}, noopSender{}, session.UserFromContext, nil, nil, tmpl, cfg, logger)

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

// TestHandler_GetRegister_ExplicitConfigWins proves the config file or
// environment beats the runtime setting, in both directions: the admin setting
// is ignored while auth.allow_registration is supplied by config.
func TestHandler_GetRegister_ExplicitConfigWins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configVal  bool
		setting    string
		wantStatus int
	}{
		{name: "config disables what the setting enables", configVal: false, setting: "true", wantStatus: http.StatusFound},
		{name: "config enables what the setting disables", configVal: true, setting: "false", wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFullHandlerFixtureAll(t, true, 5, 15, func(cfg *config.Config) {
				cfg.Auth.AllowRegistration = tt.configVal
				cfg.Auth.AllowRegistrationSet = true
			}, noopSender{})
			f.settings.values["allow_registration"] = tt.setting

			req := httptest.NewRequest(http.MethodGet, "/register", nil)
			rec := httptest.NewRecorder()
			f.handler.GetRegister(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("GetRegister status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusFound {
				if loc := rec.Header().Get("Location"); !strings.Contains(loc, "registration-disabled") {
					t.Errorf("redirect = %q, want it to mention registration-disabled", loc)
				}
			}
		})
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

// TestHandler_PostLogin_RdBackslashRejected verifies that backslash variants
// of protocol-relative URLs in the passage_rd cookie or rd form field are
// rejected (browsers treat "/\evil.com" as "//evil.com").
func TestHandler_PostLogin_RdBackslashRejected(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	if _, err := f.userSvc.Register(context.Background(), "rdslashuser", "rdslash@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	tests := []struct {
		name  string
		rdArg string
		useCk bool
	}{
		{"rd form field backslash", "/\\evil.example.com", false},
		{"passage_rd cookie backslash", "/\\evil.example.com", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("username", "rdslashuser")
			form.Set("password", "password123")
			if !tc.useCk {
				form.Set("rd", tc.rdArg)
			}

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.useCk {
				req.AddCookie(&http.Cookie{Name: "passage_rd", Value: tc.rdArg})
			}
			rec := httptest.NewRecorder()
			f.handler.PostLogin(rec, req)

			res := rec.Result()
			if res.StatusCode != http.StatusFound {
				t.Fatalf("PostLogin: got status %d, want %d", res.StatusCode, http.StatusFound)
			}
			// The sanitized value must be a same-site relative path. (net/http
			// strips raw backslashes from Cookie.Value before the handler runs,
			// so the cookie case arrives pre-sanitized.)
			if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/") ||
				strings.HasPrefix(loc, "//") || strings.Contains(loc, "\\") {
				t.Errorf("PostLogin: redirect %q is not a safe relative path", loc)
			}
		})
	}

	// A well-formed path must still be honored.
	t.Run("valid path still honored", func(t *testing.T) {
		form := url.Values{}
		form.Set("username", "rdslashuser")
		form.Set("password", "password123")
		form.Set("rd", "/valid/path")

		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.handler.PostLogin(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusFound {
			t.Fatalf("PostLogin: got status %d, want %d", res.StatusCode, http.StatusFound)
		}
		if loc := res.Header.Get("Location"); loc != "/valid/path" {
			t.Errorf("PostLogin: got redirect to %q, want %q", loc, "/valid/path")
		}
	})
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

// ─── Group E: Protocol-relative open redirect (//evil.com) ───────────────────

// TestHandler_PostLogin_ProtocolRelativeOpenRedirect verifies that a
// protocol-relative URL in the rd form field or passage_rd cookie is rejected.
// Browsers treat "//evil.com/path" as an absolute URL, so it must be blocked.
func TestHandler_PostLogin_ProtocolRelativeOpenRedirect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rdField  string
		rdCookie string
		wantDest string // expected redirect destination after login
	}{
		{
			name:     "protocol-relative rd field is rejected",
			rdField:  "//evil.com/steal",
			wantDest: "/",
		},
		{
			name:     "protocol-relative passage_rd cookie is rejected",
			rdCookie: "//evil.com/steal",
			wantDest: "/",
		},
		{
			name:     "valid rd field starting with single slash is accepted",
			rdField:  "/dashboard",
			wantDest: "/dashboard",
		},
		{
			name:     "valid passage_rd cookie starting with single slash is accepted",
			rdCookie: "/target/path",
			wantDest: "/target/path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFullHandlerFixture(t, true)

			// Register a user to log in with.
			username := strings.ReplaceAll(tc.name, " ", "")
			if _, err := f.userSvc.Register(context.Background(), username, username+"@example.com", "password123"); err != nil {
				t.Fatalf("Register: %v", err)
			}

			form := url.Values{}
			form.Set("username", username)
			form.Set("password", "password123")
			if tc.rdField != "" {
				form.Set("rd", tc.rdField)
			}

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.rdCookie != "" {
				req.AddCookie(&http.Cookie{Name: "passage_rd", Value: tc.rdCookie})
			}
			rec := httptest.NewRecorder()
			f.handler.PostLogin(rec, req)

			res := rec.Result()
			if res.StatusCode != http.StatusFound {
				t.Errorf("%s: got status %d, want %d", tc.name, res.StatusCode, http.StatusFound)
			}

			loc := res.Header.Get("Location")
			if loc != tc.wantDest {
				t.Errorf("%s: got redirect to %q, want %q", tc.name, loc, tc.wantDest)
			}

			// For rejected evil destinations, additionally ensure we did NOT
			// redirect to anything containing the evil host.
			if strings.Contains(tc.rdField, "evil.com") || strings.Contains(tc.rdCookie, "evil.com") {
				if strings.Contains(loc, "evil.com") {
					t.Errorf("%s: redirected to %q which contains evil.com — open redirect!", tc.name, loc)
				}
			}
		})
	}
}

// ─── Group F: PostResetRequest timing ────────────────────────────────────────

// TestHandler_PostResetRequest_MinimumResponseTime verifies that PostResetRequest
// always takes at least 200ms, defeating email-enumeration timing attacks.
func TestHandler_PostResetRequest_MinimumResponseTime(t *testing.T) {
	// Not parallel — this test measures wall time and should not compete.
	// Using t.Parallel() here would make the 200ms assertion flaky under load.

	tests := []struct {
		name  string
		email string
	}{
		{
			name:  "unknown email (fast path without timing guard would be sub-ms)",
			email: "nobody@nowhere.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHandlerFixture(t, true)

			form := url.Values{}
			form.Set("email", tc.email)

			req := httptest.NewRequest(http.MethodPost, "/reset", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			start := time.Now()
			h.PostResetRequest(rec, req)
			elapsed := time.Since(start)

			const minResponseTime = 200 * time.Millisecond
			if elapsed < minResponseTime {
				t.Errorf("%s: response took %v, want at least %v", tc.name, elapsed, minResponseTime)
			}

			// The response must still be 200 with the success message.
			res := rec.Result()
			if res.StatusCode != http.StatusOK {
				t.Errorf("%s: got status %d, want %d", tc.name, res.StatusCode, http.StatusOK)
			}
		})
	}
}

// ─── Auth method flag tests ───────────────────────────────────────────────────

// disabledSettings is a test-only settingsReader that returns "false" for any key.
type disabledSettings struct{}

func (disabledSettings) Get(_ context.Context, _ string) (string, error) {
	return "false", nil
}

// TestHandler_PostLogin_PasswordDisabled verifies that PostLogin returns 403
// when the auth_password_enabled setting is "false".
func TestHandler_PostLogin_PasswordDisabled(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := &config.Config{
		Auth:    config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{DurationHours: 24, CookieName: "passage_session"},
	}
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	if _, err := userSvc.Register(context.Background(), "pwuser", "pwuser@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	appStore := app.NewStore(db)
	h := user.NewHandler(userSvc, nil, app.NewService(appStore, appStore, logger), sessionSvc, disabledSettings{}, noopSender{}, session.UserFromContext, nil, nil, tmpl, cfg, logger)

	form := url.Values{}
	form.Set("username", "pwuser")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.PostLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("PostLogin with password disabled: got status %d, want %d", res.StatusCode, http.StatusForbidden)
	}
}

// failingAppLister satisfies user.AppLister and always errors.
type failingAppLister struct{}

func (failingAppLister) ListAppsForUser(_ context.Context, _ string) ([]*app.App, error) {
	return nil, errors.New("lister boom")
}

func (failingAppLister) GetByClientID(_ context.Context, _ string) (*app.App, error) {
	return nil, errors.New("lister boom")
}

func (failingAppLister) FavoriteIDs(_ context.Context, _ string) (map[string]bool, error) {
	return nil, errors.New("lister boom")
}

func (failingAppLister) ToggleFavorite(_ context.Context, _, _ string) (bool, bool, error) {
	return false, false, errors.New("lister boom")
}

// TestHandler_GetDashboard_EmptyState verifies the dashboard renders 200 for a
// non-admin user with no apps (this branch does not reach the flash partial;
// see TestHandler_GetDashboard_AppsWithFlash for the .Flash regression pin).
func TestHandler_GetDashboard_EmptyState(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u, err := f.userSvc.Register(context.Background(), "dashuser", "dash@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	f.handler.GetDashboard(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GetDashboard: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "My Apps") {
		t.Error("GetDashboard: body missing page title")
	}
	if !strings.Contains(body, "Contact your administrator to get access.") {
		t.Error("GetDashboard: body missing empty state")
	}
}

// TestHandler_GetDashboard_AppsWithFlash verifies a user with granted apps sees
// them, and that a ?flash= code renders the flash partial end to end.
// Regression guard: this is the only dashboard branch that executes the
// shared flash partial, which evaluates .Flash — a dashboard data struct
// without that field turns every GET / into a 500 (PR #2 regression).
func TestHandler_GetDashboard_AppsWithFlash(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u, err := f.userSvc.Register(context.Background(), "dashapps", "dashapps@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	a := &app.App{Slug: "grafana", Name: "Grafana", HostPattern: "grafana.lab.local", IsActive: true}
	if err := f.appSvc.Create(context.Background(), a); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	if err := f.appSvc.GrantAccess(context.Background(), u.ID, a.ID); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?flash=registered", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	f.handler.GetDashboard(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GetDashboard: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Grafana") {
		t.Error("GetDashboard: body missing granted app name")
	}
	if !strings.Contains(body, "grafana.lab.local") {
		t.Error("GetDashboard: body missing app host pattern")
	}
	if !strings.Contains(body, "Account created. Please sign in.") {
		t.Error("GetDashboard: body missing flash message")
	}
}

// withChiParam injects one chi route URL parameter into the request context.
func withChiParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// seedFavoriteApps creates three apps in name order for the user and returns
// them in that order.
func seedFavoriteApps(t *testing.T, f *handlerFixture, userID string) []*app.App {
	t.Helper()
	ctx := context.Background()
	apps := []*app.App{
		{Slug: "alpha", Name: "Alpha", HostPattern: "alpha.lab.local", IsActive: true},
		{Slug: "bravo", Name: "Bravo", HostPattern: "bravo.lab.local", IsActive: true},
		{Slug: "charlie", Name: "Charlie", HostPattern: "charlie.lab.local", IsActive: true},
	}
	for _, a := range apps {
		if err := f.appSvc.Create(ctx, a); err != nil {
			t.Fatalf("seed app %q: %v", a.Slug, err)
		}
		if err := f.appSvc.GrantAccess(ctx, userID, a.ID); err != nil {
			t.Fatalf("grant access to %q: %v", a.Slug, err)
		}
	}
	return apps
}

// TestHandler_GetDashboard_PinnedFirst pins the last app in name order and
// proves it moves to the top while the other two keep their order.
func TestHandler_GetDashboard_PinnedFirst(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFullHandlerFixture(t, true)
	u, err := f.userSvc.Register(ctx, "dashpin", "dashpin@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	apps := seedFavoriteApps(t, f, u.ID)

	if _, _, err := f.appSvc.ToggleFavorite(ctx, u.ID, apps[2].ID); err != nil {
		t.Fatalf("ToggleFavorite: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	f.handler.GetDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GetDashboard: got status %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	charlie := strings.Index(body, "Charlie")
	alpha := strings.Index(body, "Alpha")
	bravo := strings.Index(body, "Bravo")
	if charlie < 0 || alpha < 0 || bravo < 0 {
		t.Fatalf("GetDashboard: missing app names (charlie=%d alpha=%d bravo=%d)", charlie, alpha, bravo)
	}
	if !(charlie < alpha && alpha < bravo) {
		t.Errorf("GetDashboard: order charlie=%d alpha=%d bravo=%d, want pinned Charlie first then Alpha, Bravo", charlie, alpha, bravo)
	}
}

// TestHandler_GetDashboard_FavoriteMarkup pins one app and checks both the
// star state and the POST target for every card.
func TestHandler_GetDashboard_FavoriteMarkup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFullHandlerFixture(t, true)
	u, err := f.userSvc.Register(ctx, "dashstar", "dashstar@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	apps := seedFavoriteApps(t, f, u.ID)
	if _, _, err := f.appSvc.ToggleFavorite(ctx, u.ID, apps[0].ID); err != nil {
		t.Fatalf("ToggleFavorite: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	f.handler.GetDashboard(rec, req)

	body := rec.Body.String()
	for _, a := range apps {
		if !strings.Contains(body, `action="/apps/`+a.ID+`/favorite"`) {
			t.Errorf("GetDashboard: missing pin form for %q", a.Slug)
		}
	}
	if !strings.Contains(body, "favorite-toggle is-favorite") {
		t.Error("GetDashboard: pinned app is missing the is-favorite state")
	}
	if strings.Count(body, "favorite-toggle is-favorite") != 1 {
		t.Errorf("GetDashboard: got %d pinned stars, want 1", strings.Count(body, "favorite-toggle is-favorite"))
	}
	if !strings.Contains(body, `aria-label="Unpin Alpha"`) {
		t.Error("GetDashboard: pinned star is missing the unpin label")
	}
	if !strings.Contains(body, `aria-label="Pin Bravo to the top"`) {
		t.Error("GetDashboard: unpinned star is missing the pin label")
	}
}

// TestHandler_PostToggleFavorite flips a pin through the handler and proves the
// redirect target plus the stored state, twice, so pin and unpin both work.
func TestHandler_PostToggleFavorite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFullHandlerFixture(t, true)
	u, err := f.userSvc.Register(ctx, "dashtoggle", "dashtoggle@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	apps := seedFavoriteApps(t, f, u.ID)
	target := apps[1]

	for _, want := range []bool{true, false} {
		req := httptest.NewRequest(http.MethodPost, "/apps/"+target.ID+"/favorite", nil)
		req = req.WithContext(session.WithUser(req.Context(), u))
		req = withChiParam(req, "id", target.ID)
		rec := httptest.NewRecorder()
		f.handler.PostToggleFavorite(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("PostToggleFavorite: got status %d, want %d", rec.Code, http.StatusFound)
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("PostToggleFavorite: Location = %q, want %q", loc, "/")
		}
		ids, err := f.appSvc.FavoriteIDs(ctx, u.ID)
		if err != nil {
			t.Fatalf("FavoriteIDs: %v", err)
		}
		if ids[target.ID] != want {
			t.Errorf("after toggle: pinned = %v, want %v", ids[target.ID], want)
		}
	}
}

// TestHandler_PostToggleFavorite_NoAccess proves a toggle for an app the user
// cannot reach still redirects and changes nothing.
func TestHandler_PostToggleFavorite_NoAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFullHandlerFixture(t, true)
	u, err := f.userSvc.Register(ctx, "dashnoaccess", "dashnoaccess@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	apps := seedFavoriteApps(t, f, u.ID)
	target := apps[0]
	if err := f.appSvc.RevokeAccess(ctx, u.ID, target.ID); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/apps/"+target.ID+"/favorite", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	req = withChiParam(req, "id", target.ID)
	rec := httptest.NewRecorder()
	f.handler.PostToggleFavorite(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("PostToggleFavorite: got status %d, want %d", rec.Code, http.StatusFound)
	}
	ids, err := f.appSvc.FavoriteIDs(ctx, u.ID)
	if err != nil {
		t.Fatalf("FavoriteIDs: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("FavoriteIDs = %v, want empty", ids)
	}
}

// TestHandler_PostToggleFavorite_Unauthenticated proves the route refuses to
// act without a user in context.
func TestHandler_PostToggleFavorite_Unauthenticated(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	req := httptest.NewRequest(http.MethodPost, "/apps/whatever/favorite", nil)
	req = withChiParam(req, "id", "whatever")
	rec := httptest.NewRecorder()
	f.handler.PostToggleFavorite(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("PostToggleFavorite: got status %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("PostToggleFavorite: Location = %q, want %q", loc, "/login")
	}
}

// TestHandler_GetDashboard_ListerError verifies an app-listing failure returns
// 500 instead of a partial page.
func TestHandler_GetDashboard_ListerError(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := &config.Config{
		Auth:    config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{DurationHours: 24, CookieName: "passage_session"},
	}
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	u, err := userSvc.Register(context.Background(), "dasherr", "dasherr@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	h := user.NewHandler(userSvc, nil, failingAppLister{}, sessionSvc, noopSettings{}, noopSender{}, session.UserFromContext, nil, nil, tmpl, cfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	h.GetDashboard(rec, req)

	if res := rec.Result(); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("GetDashboard lister error: got status %d, want %d", res.StatusCode, http.StatusInternalServerError)
	}
}
