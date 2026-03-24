package forwardauth_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/forwardauth"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// testCfg returns a minimal Config for forwardauth tests.
func testCfg() *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			AllowRegistration: true,
			BcryptCost:        10,
		},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
	}
}

// testDeps holds all services needed by handler tests.
type testDeps struct {
	cfg        *config.Config
	userSvc    *user.Service
	userStore  *user.SQLiteStore
	sessionSvc *session.Service
	appSvc     *app.Service
	handler    *forwardauth.Handler
}

// setupDeps creates real services backed by an in-memory SQLite database and
// builds a forwardauth.Handler wired to them.
func setupDeps(t *testing.T) *testDeps {
	t.Helper()
	db := testutil.NewTestDB(t)
	cfg := testCfg()

	userStore := user.NewStore(db)
	userSvc := user.NewService(userStore, userStore, cfg)

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, cfg, slog.Default())

	appStore := app.NewStore(db)
	appSvc := app.NewService(appStore, appStore, slog.Default())

	handler := forwardauth.NewHandler(sessionSvc, appSvc, cfg, slog.Default())

	return &testDeps{
		cfg:        cfg,
		userSvc:    userSvc,
		userStore:  userStore,
		sessionSvc: sessionSvc,
		appSvc:     appSvc,
		handler:    handler,
	}
}

// createUserAndSession is a helper that registers a user and creates a session
// for them, returning the user, session token, and its expiry.
func createUserAndSession(t *testing.T, deps *testDeps, username string) (*user.User, string) {
	t.Helper()
	ctx := context.Background()
	u, err := deps.userSvc.Register(ctx, username, username+"@example.com", "password123")
	if err != nil {
		t.Fatalf("Register %q: %v", username, err)
	}
	token, _, err := deps.sessionSvc.CreateSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession for %q: %v", username, err)
	}
	return u, token
}

// createApp is a helper that creates an active app with the given slug and host pattern.
func createApp(t *testing.T, deps *testDeps, slug, hostPattern string) *app.App {
	t.Helper()
	ctx := context.Background()
	a := &app.App{
		Slug:        slug,
		Name:        slug,
		HostPattern: hostPattern,
		IsActive:    true,
	}
	if err := deps.appSvc.Create(ctx, a); err != nil {
		t.Fatalf("Create app %q: %v", slug, err)
	}
	return a
}

// newRouter builds a chi router with the handler's routes registered.
func newRouter(h *forwardauth.Handler) *chi.Mux {
	r := chi.NewRouter()
	h.Routes(r)
	return r
}

// TestNginxAuth_ValidSession verifies that a valid session + app + access
// combination returns 200 with all identity headers.
func TestNginxAuth_ValidSession(t *testing.T) {
	t.Parallel()
	deps := setupDeps(t)
	u, token := createUserAndSession(t, deps, "nginxvalid")
	a := createApp(t, deps, "grafana", "grafana.home.example.com")
	if err := deps.appSvc.GrantAccess(context.Background(), u.ID, a.ID); err != nil {
		t.Fatalf("GrantAccess: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/nginx", nil)
	r.Header.Set("X-Original-URL", "https://grafana.home.example.com/dashboard")
	r.AddCookie(&http.Cookie{Name: deps.cfg.Session.CookieName, Value: token})
	w := httptest.NewRecorder()

	newRouter(deps.handler).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("NginxAuth valid session: got status %d, want 200", w.Code)
	}
	checkHeader(t, w, "X-Passage-Username", u.Username)
	checkHeader(t, w, "X-Passage-Email", u.Email)
	checkHeader(t, w, "X-Passage-User-ID", u.ID)
	checkHeader(t, w, "X-Passage-Is-Admin", "false")
}

// TestNginxAuth_NoSession verifies that a request without a session cookie
// returns 401.
func TestNginxAuth_NoSession(t *testing.T) {
	t.Parallel()
	deps := setupDeps(t)
	createApp(t, deps, "grafana2", "grafana2.home.example.com")

	r := httptest.NewRequest(http.MethodGet, "/auth/nginx", nil)
	r.Header.Set("X-Original-URL", "https://grafana2.home.example.com/dashboard")
	// No cookie set.
	w := httptest.NewRecorder()

	newRouter(deps.handler).ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("NginxAuth no session: got status %d, want 401", w.Code)
	}
}

// TestNginxAuth_NoAccess verifies that a valid session for a user without app
// access returns 403 Forbidden (authenticated but not authorized).
func TestNginxAuth_NoAccess(t *testing.T) {
	t.Parallel()
	deps := setupDeps(t)
	_, token := createUserAndSession(t, deps, "noaccess")
	createApp(t, deps, "privateapp", "private.home.example.com")
	// Do NOT grant access.

	r := httptest.NewRequest(http.MethodGet, "/auth/nginx", nil)
	r.Header.Set("X-Original-URL", "https://private.home.example.com/secret")
	r.AddCookie(&http.Cookie{Name: deps.cfg.Session.CookieName, Value: token})
	w := httptest.NewRecorder()

	newRouter(deps.handler).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("NginxAuth no access: got status %d, want 403", w.Code)
	}
}

// TestNginxAuth_NoAppForHost verifies that a request for a host not registered
// in Passage returns 401.
func TestNginxAuth_NoAppForHost(t *testing.T) {
	t.Parallel()
	deps := setupDeps(t)
	_, token := createUserAndSession(t, deps, "hosttest")
	// No app registered at all.

	r := httptest.NewRequest(http.MethodGet, "/auth/nginx", nil)
	r.Header.Set("X-Original-URL", "https://unknown.other.example.com/page")
	r.AddCookie(&http.Cookie{Name: deps.cfg.Session.CookieName, Value: token})
	w := httptest.NewRecorder()

	newRouter(deps.handler).ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("NginxAuth no app for host: got status %d, want 401", w.Code)
	}
}

// TestNginxAuth_ExpiredSession verifies that an expired session returns 401.
func TestNginxAuth_ExpiredSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create a fresh DB and services where sessions expire immediately.
	db2 := testutil.NewTestDB(t)
	expiredCfg := &config.Config{
		Auth:    config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{DurationHours: 0, CookieName: "passage_session"},
	}
	userStore2 := user.NewStore(db2)
	userSvc2 := user.NewService(userStore2, userStore2, expiredCfg)
	sessionStore2 := session.NewStore(db2)
	sessionSvc2 := session.NewService(sessionStore2, userStore2, expiredCfg, slog.Default())
	appStore2 := app.NewStore(db2)
	appSvc2 := app.NewService(appStore2, appStore2, slog.Default())
	h2 := forwardauth.NewHandler(sessionSvc2, appSvc2, expiredCfg, slog.Default())

	u2, err := userSvc2.Register(ctx, "expuser2", "expuser2@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	a2 := &app.App{
		Slug:        "expapp2",
		Name:        "expapp2",
		HostPattern: "expapp2.home.example.com",
		IsActive:    true,
	}
	if err := appSvc2.Create(ctx, a2); err != nil {
		t.Fatalf("Create app: %v", err)
	}
	if err := appSvc2.GrantAccess(ctx, u2.ID, a2.ID); err != nil {
		t.Fatalf("GrantAccess: %v", err)
	}

	// Insert a session directly with a past expiry so it is already expired.
	// app_id is NULL because forward-auth sessions are not app-scoped at the session level;
	// app resolution happens at request time based on the X-Original-URL host.
	pastExpiry := time.Now().UTC().Add(-1 * time.Hour)
	const insertSQL = `INSERT INTO sessions (id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		VALUES ('expired-token', ?, NULL, '', '', ?, ?)`
	if _, err := db2.ExecContext(ctx, insertSQL, u2.ID, pastExpiry, time.Now().UTC()); err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/nginx", nil)
	r.Header.Set("X-Original-URL", "https://expapp2.home.example.com/page")
	r.AddCookie(&http.Cookie{Name: expiredCfg.Session.CookieName, Value: "expired-token"})
	w := httptest.NewRecorder()

	newRouter(h2).ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("NginxAuth expired session: got status %d, want 401", w.Code)
	}
}

// TestTraefikAuth_ValidSession verifies the Traefik variant with X-Forwarded-Host.
func TestTraefikAuth_ValidSession(t *testing.T) {
	t.Parallel()
	deps := setupDeps(t)
	u, token := createUserAndSession(t, deps, "traefikvalid")
	a := createApp(t, deps, "traefikapp", "traefikapp.home.example.com")
	if err := deps.appSvc.GrantAccess(context.Background(), u.ID, a.ID); err != nil {
		t.Fatalf("GrantAccess: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/traefik", nil)
	r.Header.Set("X-Forwarded-Host", "traefikapp.home.example.com")
	r.AddCookie(&http.Cookie{Name: deps.cfg.Session.CookieName, Value: token})
	w := httptest.NewRecorder()

	newRouter(deps.handler).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("TraefikAuth valid session: got status %d, want 200", w.Code)
	}
	checkHeader(t, w, "X-Passage-Username", u.Username)
	checkHeader(t, w, "X-Passage-User-ID", u.ID)
}

// TestAuthStart_WithRd verifies that a valid relative rd param results in a
// passage_rd cookie being set and a redirect to /login.
func TestAuthStart_WithRd(t *testing.T) {
	t.Parallel()
	deps := setupDeps(t)

	r := httptest.NewRequest(http.MethodGet, "/auth/start?rd=/protected/page", nil)
	w := httptest.NewRecorder()

	newRouter(deps.handler).ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("AuthStart with rd: got status %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("AuthStart with rd: got Location %q, want /login", loc)
	}

	// Verify passage_rd cookie is set.
	var rdCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "passage_rd" {
			rdCookie = c
			break
		}
	}
	if rdCookie == nil {
		t.Fatal("AuthStart with rd: passage_rd cookie not set")
	}
	if rdCookie.Value != "/protected/page" {
		t.Errorf("AuthStart with rd: passage_rd value = %q, want /protected/page", rdCookie.Value)
	}
	if !rdCookie.HttpOnly {
		t.Error("AuthStart with rd: passage_rd cookie must be HttpOnly")
	}
}

// TestAuthStart_OpenRedirect verifies that an external (non-relative) rd param
// is rejected: no passage_rd cookie is set and the redirect is still to /login.
func TestAuthStart_OpenRedirect(t *testing.T) {
	t.Parallel()
	deps := setupDeps(t)

	r := httptest.NewRequest(http.MethodGet, "/auth/start?rd=https://evil.example.com/steal", nil)
	w := httptest.NewRecorder()

	newRouter(deps.handler).ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("AuthStart open redirect: got status %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("AuthStart open redirect: got Location %q, want /login", loc)
	}

	// The passage_rd cookie must NOT be set for external URLs.
	for _, c := range w.Result().Cookies() {
		if c.Name == "passage_rd" {
			t.Errorf("AuthStart open redirect: passage_rd cookie should not be set, got value %q", c.Value)
		}
	}
}

// TestSignOut verifies that sign-out clears the session cookie and returns 200.
func TestSignOut(t *testing.T) {
	t.Parallel()
	deps := setupDeps(t)
	_, token := createUserAndSession(t, deps, "signoutuser")

	r := httptest.NewRequest(http.MethodPost, "/auth/sign_out", nil)
	r.AddCookie(&http.Cookie{Name: deps.cfg.Session.CookieName, Value: token})
	w := httptest.NewRecorder()

	newRouter(deps.handler).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("SignOut: got status %d, want 200", w.Code)
	}

	// Verify the session cookie is cleared.
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == deps.cfg.Session.CookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie != nil && sessionCookie.MaxAge != -1 && !sessionCookie.Expires.IsZero() && sessionCookie.Expires.After(time.Now()) {
		t.Error("SignOut: session cookie is not cleared")
	}
}

// checkHeader is a test helper that asserts a response header has the expected value.
func checkHeader(t *testing.T, w *httptest.ResponseRecorder, header, want string) {
	t.Helper()
	got := w.Header().Get(header)
	if got != want {
		t.Errorf("header %q: got %q, want %q", header, got, want)
	}
}
