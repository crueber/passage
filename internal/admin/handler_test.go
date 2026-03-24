package admin_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// noopMailer satisfies the email.Sender interface with a no-op implementation.
type noopMailer struct{}

func (noopMailer) SendPasswordReset(_ context.Context, _, _, _ string) error { return nil }

// noopCredentialCounter satisfies the credentialCounter interface with a zero-returning implementation.
type noopCredentialCounter struct{}

func (noopCredentialCounter) CountByUser(_ context.Context, _ string) (int, error) { return 0, nil }

// fixture holds the full dependency graph for admin handler tests.
type fixture struct {
	db           interface{ Close() error }
	userStore    *user.SQLiteStore
	userSvc      *user.Service
	sessionStore *session.SQLiteStore
	sessionSvc   *session.Service
	appStore     *app.SQLiteStore
	appSvc       *app.Service
	settings     admin.SettingsStore
	handler      *admin.Handler
	cfg          *config.Config
}

// newFixture builds all dependencies wired to an in-memory SQLite database.
func newFixture(t *testing.T) *fixture {
	t.Helper()

	database := testutil.NewTestDB(t)

	cfg := &config.Config{
		Auth: config.AuthConfig{
			AllowRegistration: true,
			BcryptCost:        10,
		},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
		Server: config.ServerConfig{
			BaseURL: "http://localhost:8080",
		},
	}

	userStore := user.NewStore(database)
	userSvc := user.NewService(userStore, userStore, cfg)

	sessionStore := session.NewStore(database)
	sessionSvc := session.NewService(sessionStore, userStore, cfg, slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))

	appStore := app.NewStore(database)
	appSvc := app.NewService(appStore, appStore, slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))

	settings := admin.NewSQLiteSettingsStore(database)

	tmpl, err := web.Parse(web.TemplateFS)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	h := admin.NewHandler(userStore, userSvc, sessionSvc, appSvc, settings, noopCredentialCounter{}, noopMailer{}, tmpl, cfg, logger)

	return &fixture{
		db:           database,
		userStore:    userStore,
		userSvc:      userSvc,
		sessionStore: sessionStore,
		sessionSvc:   sessionSvc,
		appStore:     appStore,
		appSvc:       appSvc,
		settings:     settings,
		handler:      h,
		cfg:          cfg,
	}
}

// createAdminUser creates an active admin user and returns it.
func createAdminUser(t *testing.T, f *fixture, username, email string) *user.User {
	t.Helper()
	// Use the service to register; service-level auth is tested elsewhere.
	if _, err := f.userSvc.Register(context.Background(), username, email, "password123"); err != nil {
		t.Fatalf("register user %q: %v", username, err)
	}
	// Fetch back to get the ID, then update to make admin.
	created, err := f.userStore.GetByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("get user %q: %v", username, err)
	}
	created.IsAdmin = true
	if err := f.userStore.Update(context.Background(), created); err != nil {
		t.Fatalf("make user admin %q: %v", username, err)
	}
	return created
}

// createSession creates a session for the given user and returns the token.
func createSession(t *testing.T, f *fixture, userID string) string {
	t.Helper()
	token, _, err := f.sessionSvc.CreateSession(context.Background(), userID, nil, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return token
}

// buildAdminRouter creates a chi router with the admin middleware and handler routes.
func buildAdminRouter(f *fixture) http.Handler {
	r := chi.NewRouter()
	r.Route("/admin", func(r chi.Router) {
		r.Use(admin.RequireAdmin(f.sessionSvc, f.cfg))
		f.handler.Routes(r)
	})
	return r
}

// adminRequest performs an HTTP request with an admin session cookie.
// cookieName is passed explicitly so callers can use f.cfg.Session.CookieName.
func adminRequest(t *testing.T, router http.Handler, method, path, cookie, cookieName string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// ─── Middleware tests ─────────────────────────────────────────────────────────

func TestAdminMiddleware_RedirectsUnauthenticated(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	router := buildAdminRouter(f)

	tests := []struct {
		name string
		path string
	}{
		{"dashboard", "/admin"},
		{"users", "/admin/users"},
		{"apps", "/admin/apps"},
		{"sessions", "/admin/sessions"},
		{"settings", "/admin/settings"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := adminRequest(t, router, http.MethodGet, tc.path, "", f.cfg.Session.CookieName, nil, "")
			res := rec.Result()
			if res.StatusCode != http.StatusFound {
				t.Errorf("%s: got status %d, want %d (redirect)", tc.path, res.StatusCode, http.StatusFound)
			}
			loc := res.Header.Get("Location")
			if !strings.Contains(loc, "/login") {
				t.Errorf("%s: redirect target %q does not contain /login", tc.path, loc)
			}
		})
	}
}

func TestAdminMiddleware_RedirectsNonAdmin(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Create a non-admin user and session.
	if _, err := f.userSvc.Register(context.Background(), "nonadmin", "nonadmin@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}
	nonadmin, err := f.userStore.GetByUsername(context.Background(), "nonadmin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	token := createSession(t, f, nonadmin.ID)

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodGet, "/admin", token, f.cfg.Session.CookieName, nil, "")
	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("non-admin: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

func TestAdminDashboard(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, admin.ID)

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodGet, "/admin", token, f.cfg.Session.CookieName, nil, "")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("dashboard: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Errorf("dashboard: response does not contain 'Dashboard'")
	}
	// Should contain stat tiles.
	if !strings.Contains(body, "stat-tile") || !strings.Contains(body, "stat-number") {
		t.Errorf("dashboard: response does not contain stat tiles")
	}
}

// ─── Users ────────────────────────────────────────────────────────────────────

func TestAdminUsers_List(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	// Create a second user to verify it appears in the list.
	if _, err := f.userSvc.Register(context.Background(), "listuser", "listuser@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodGet, "/admin/users", token, f.cfg.Session.CookieName, nil, "")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("user list: got status %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "listuser") {
		t.Errorf("user list: response does not contain 'listuser'")
	}
	if !strings.Contains(body, "admin") {
		t.Errorf("user list: response does not contain admin username")
	}
}

func TestAdminUsers_Create(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	form := url.Values{}
	form.Set("username", "newcreateduser")
	form.Set("email", "newcreated@example.com")
	form.Set("name", "New Created User")
	form.Set("password", "password123")
	form.Set("is_active", "on")

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodPost, "/admin/users", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Errorf("create user: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "/admin/users") {
		t.Errorf("create user: redirect %q does not go to /admin/users", loc)
	}

	// Verify the user was actually created.
	created, err := f.userStore.GetByUsername(context.Background(), "newcreateduser")
	if err != nil {
		t.Fatalf("get created user: %v", err)
	}
	if created.Email != "newcreated@example.com" {
		t.Errorf("create user: got email %q, want %q", created.Email, "newcreated@example.com")
	}
}

// TestAdminUsers_Update verifies that an admin can update a user's profile.
func TestAdminUsers_Update(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	// Create a target user to update.
	if _, err := f.userSvc.Register(context.Background(), "updatetarget", "updatetarget@example.com", "password123"); err != nil {
		t.Fatalf("register target: %v", err)
	}
	target, err := f.userStore.GetByUsername(context.Background(), "updatetarget")
	if err != nil {
		t.Fatalf("get target user: %v", err)
	}

	router := buildAdminRouter(f)

	// GET the edit form — should be 200.
	rec := adminRequest(t, router, http.MethodGet, "/admin/users/"+target.ID, token, f.cfg.Session.CookieName, nil, "")
	if rec.Result().StatusCode != http.StatusOK {
		t.Errorf("GET edit user: got %d, want 200", rec.Result().StatusCode)
	}

	// POST updated fields.
	form := url.Values{}
	form.Set("username", "updatetarget")
	form.Set("email", "updatetarget@example.com")
	form.Set("name", "Updated Name")
	form.Set("is_active", "on")

	rec = adminRequest(t, router, http.MethodPost, "/admin/users/"+target.ID, token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Errorf("POST update user: got %d, want 302", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "flash=updated") {
		t.Errorf("POST update user: redirect %q does not contain flash=updated", loc)
	}

	// Verify the DB mutation.
	updated, err := f.userStore.GetByID(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("get updated user: %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("update user: got name %q, want %q", updated.Name, "Updated Name")
	}
}

func TestAdminUsers_Delete(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	// Create a user to delete.
	if _, err := f.userSvc.Register(context.Background(), "todelete", "todelete@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}
	target, err := f.userStore.GetByUsername(context.Background(), "todelete")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodPost,
		"/admin/users/"+target.ID+"/delete", token, f.cfg.Session.CookieName, nil, "")
	res := rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Errorf("delete user: got status %d, want %d", res.StatusCode, http.StatusFound)
	}

	// Verify the user is gone.
	_, err = f.userStore.GetByUsername(context.Background(), "todelete")
	if err == nil {
		t.Error("delete user: user still exists after delete")
	}
}

func TestAdminUsers_ResetPasswordEmail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	// Create a user to reset password for.
	if _, err := f.userSvc.Register(context.Background(), "resetuser", "resetuser@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}
	target, err := f.userStore.GetByUsername(context.Background(), "resetuser")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodPost,
		"/admin/users/"+target.ID+"/reset-password", token, f.cfg.Session.CookieName, nil, "")
	res := rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Errorf("reset password: got %d, want 302", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "reset-sent") {
		t.Errorf("reset password: redirect %q does not contain 'reset-sent'", loc)
	}
}

// TestAdminUsers_SelfDeleteForbidden verifies that an admin cannot delete their own account.
func TestAdminUsers_SelfDeleteForbidden(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodPost,
		"/admin/users/"+adminUser.ID+"/delete", token, f.cfg.Session.CookieName, nil, "")
	res := rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Errorf("self-delete: got status %d, want %d", res.StatusCode, http.StatusFound)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "self-delete-forbidden") {
		t.Errorf("self-delete: redirect %q does not contain self-delete-forbidden", loc)
	}

	// The admin should still exist.
	_, err := f.userStore.GetByID(context.Background(), adminUser.ID)
	if err != nil {
		t.Errorf("self-delete: admin user was deleted: %v", err)
	}
}

// ─── Apps CRUD ────────────────────────────────────────────────────────────────

func TestAdminApps_CRUD(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	t.Run("list empty", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/apps", token, f.cfg.Session.CookieName, nil, "")
		if rec.Result().StatusCode != http.StatusOK {
			t.Errorf("apps list: got %d, want 200", rec.Result().StatusCode)
		}
	})

	t.Run("create", func(t *testing.T) {
		form := url.Values{}
		form.Set("slug", "test-app")
		form.Set("name", "Test App")
		form.Set("description", "A test application")
		form.Set("host_pattern", "test.example.com")
		form.Set("is_active", "on")

		rec := adminRequest(t, router, http.MethodPost, "/admin/apps", token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
		res := rec.Result()

		if res.StatusCode != http.StatusFound {
			t.Errorf("create app: got %d, want 302", res.StatusCode)
		}

		a, err := f.appStore.GetBySlug(context.Background(), "test-app")
		if err != nil {
			t.Fatalf("get app by slug: %v", err)
		}
		if a.Name != "Test App" {
			t.Errorf("create app: got name %q, want %q", a.Name, "Test App")
		}
	})

	t.Run("edit", func(t *testing.T) {
		a, err := f.appStore.GetBySlug(context.Background(), "test-app")
		if err != nil {
			t.Fatalf("get app: %v", err)
		}

		rec := adminRequest(t, router, http.MethodGet, "/admin/apps/"+a.ID, token, f.cfg.Session.CookieName, nil, "")
		if rec.Result().StatusCode != http.StatusOK {
			t.Errorf("edit app form: got %d, want 200", rec.Result().StatusCode)
		}

		form := url.Values{}
		form.Set("slug", "test-app")
		form.Set("name", "Test App Updated")
		form.Set("description", "Updated description")
		form.Set("host_pattern", "test.example.com")
		form.Set("is_active", "on")

		rec = adminRequest(t, router, http.MethodPost, "/admin/apps/"+a.ID, token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
		if rec.Result().StatusCode != http.StatusFound {
			t.Errorf("update app: got %d, want 302", rec.Result().StatusCode)
		}

		updated, err := f.appStore.GetByID(context.Background(), a.ID)
		if err != nil {
			t.Fatalf("get updated app: %v", err)
		}
		if updated.Name != "Test App Updated" {
			t.Errorf("update app: got name %q, want %q", updated.Name, "Test App Updated")
		}
	})

	t.Run("delete", func(t *testing.T) {
		a, err := f.appStore.GetBySlug(context.Background(), "test-app")
		if err != nil {
			t.Fatalf("get app for delete: %v", err)
		}

		rec := adminRequest(t, router, http.MethodPost, "/admin/apps/"+a.ID+"/delete", token, f.cfg.Session.CookieName, nil, "")
		if rec.Result().StatusCode != http.StatusFound {
			t.Errorf("delete app: got %d, want 302", rec.Result().StatusCode)
		}

		_, err = f.appStore.GetBySlug(context.Background(), "test-app")
		if err == nil {
			t.Error("delete app: app still exists after delete")
		}
	})
}

// ─── App Access ───────────────────────────────────────────────────────────────

// TestAdminAppAccess_GrantAndRevoke verifies granting and revoking user access to an app.
func TestAdminAppAccess_GrantAndRevoke(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	// Create an app.
	a := &app.App{
		Slug:        "access-test-app",
		Name:        "Access Test App",
		HostPattern: "access.example.com",
		IsActive:    true,
	}
	if err := f.appSvc.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	created, err := f.appStore.GetBySlug(ctx, "access-test-app")
	if err != nil {
		t.Fatalf("get app by slug: %v", err)
	}
	appID := created.ID

	// Create a regular (non-admin) user.
	if _, err := f.userSvc.Register(ctx, "regularuser", "regular@example.com", "password123"); err != nil {
		t.Fatalf("register regular user: %v", err)
	}
	regularUser, err := f.userStore.GetByUsername(ctx, "regularuser")
	if err != nil {
		t.Fatalf("get regular user: %v", err)
	}

	// POST to grant access.
	form := url.Values{}
	form.Set("user_id", regularUser.ID)
	rec := adminRequest(t, router, http.MethodPost, "/admin/apps/"+appID+"/access", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Errorf("grant access: got %d, want 302", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "flash=access-granted") {
		t.Errorf("grant access: redirect %q does not contain flash=access-granted", loc)
	}

	// Verify the user now has access.
	accesses, err := f.appStore.ListUsersWithAccess(ctx, appID)
	if err != nil {
		t.Fatalf("list users with access: %v", err)
	}
	found := false
	for _, ac := range accesses {
		if ac.UserID == regularUser.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("grant access: user does not have access after grant")
	}

	// POST to revoke access.
	rec = adminRequest(t, router, http.MethodPost,
		"/admin/apps/"+appID+"/access/"+regularUser.ID+"/revoke", token, f.cfg.Session.CookieName, nil, "")
	res = rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Errorf("revoke access: got %d, want 302", res.StatusCode)
	}
	loc = res.Header.Get("Location")
	if !strings.Contains(loc, "flash=access-revoked") {
		t.Errorf("revoke access: redirect %q does not contain flash=access-revoked", loc)
	}

	// Verify the access is gone.
	accesses, err = f.appStore.ListUsersWithAccess(ctx, appID)
	if err != nil {
		t.Fatalf("list users with access after revoke: %v", err)
	}
	for _, ac := range accesses {
		if ac.UserID == regularUser.ID {
			t.Error("revoke access: user still has access after revoke")
		}
	}
}

// TestAdminAppAccess_HTMX verifies that the HTMX revoke path returns a 200 with
// an inline "revoked" indicator instead of a redirect.
func TestAdminAppAccess_HTMX(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	adminToken := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	// Create an app.
	a := &app.App{
		Slug:        "htmx-access-app",
		Name:        "HTMX Access App",
		HostPattern: "htmx-access.example.com",
		IsActive:    true,
	}
	if err := f.appSvc.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	created, err := f.appStore.GetBySlug(ctx, "htmx-access-app")
	if err != nil {
		t.Fatalf("get app by slug: %v", err)
	}
	appID := created.ID

	// Create a regular user and grant access directly.
	if _, err := f.userSvc.Register(ctx, "htmxaccessuser", "htmxaccess@example.com", "password123"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	regularUser, err := f.userStore.GetByUsername(ctx, "htmxaccessuser")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if err := f.appSvc.GrantAccess(ctx, regularUser.ID, appID); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	// POST to revoke with HX-Request header.
	req := httptest.NewRequest(http.MethodPost,
		"/admin/apps/"+appID+"/access/"+regularUser.ID+"/revoke", nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: adminToken})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("htmx revoke access: got %d, want 200", res.StatusCode)
	}
	body := rec.Body.String()
	if !strings.Contains(strings.ToLower(body), "revoked") {
		t.Errorf("htmx revoke access: response does not contain 'revoked'; got: %s", body)
	}
}

// ─── Sessions ────────────────────────────────────────────────────────────────

func TestAdminSessions_List(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodGet, "/admin/sessions", token, f.cfg.Session.CookieName, nil, "")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("sessions list: got %d, want 200", res.StatusCode)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Sessions") {
		t.Errorf("sessions list: response does not contain 'Sessions'")
	}
	// The admin user's own session should appear.
	if !strings.Contains(body, "admin") {
		t.Errorf("sessions list: response does not contain admin username")
	}
}

func TestAdminSessions_Revoke(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	adminToken := createSession(t, f, adminUser.ID)

	// Create a second session to revoke.
	if _, err := f.userSvc.Register(context.Background(), "revokeuser", "revoke@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}
	revokeUser, err := f.userStore.GetByUsername(context.Background(), "revokeuser")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	revokeToken := createSession(t, f, revokeUser.ID)

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodPost,
		"/admin/sessions/"+revokeToken+"/revoke", adminToken, f.cfg.Session.CookieName, nil, "")
	res := rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Errorf("revoke session: got %d, want 302", res.StatusCode)
	}

	// Verify the session is gone by attempting validation.
	_, _, err = f.sessionSvc.ValidateSession(context.Background(), revokeToken)
	if err == nil {
		t.Error("revoke session: session still valid after revoke")
	}
}

func TestAdminSessions_Revoke_HTMX(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	adminToken := createSession(t, f, adminUser.ID)

	if _, err := f.userSvc.Register(context.Background(), "htmxuser", "htmx@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}
	htmxUser, err := f.userStore.GetByUsername(context.Background(), "htmxuser")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	htmxToken := createSession(t, f, htmxUser.ID)

	router := buildAdminRouter(f)

	req := httptest.NewRequest(http.MethodPost, "/admin/sessions/"+htmxToken+"/revoke", nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: adminToken})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("htmx revoke: got %d, want 200", res.StatusCode)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Revoked") && !strings.Contains(body, "revoked") {
		t.Errorf("htmx revoke: response does not contain revocation indicator; got: %s", body)
	}
}

// ─── PostCreateUser validation errors ────────────────────────────────────────

func TestAdminUsers_Create_ShortPassword(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	form := url.Values{}
	form.Set("username", "shortpwuser")
	form.Set("email", "shortpw@example.com")
	form.Set("password", "abc") // 3 chars — below the 8-char minimum

	rec := adminRequest(t, router, http.MethodPost, "/admin/users", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	// Handler must re-render the form (200), not redirect.
	if res.StatusCode != http.StatusOK {
		t.Errorf("short password: got status %d, want 200 (re-render)", res.StatusCode)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Password must be at least 8 characters") {
		t.Errorf("short password: response does not contain expected error message; got: %s", body)
	}

	// No user should have been created.
	_, err := f.userStore.GetByUsername(context.Background(), "shortpwuser")
	if err == nil {
		t.Error("short password: user was created despite short password")
	}
}

func TestAdminUsers_Create_DuplicateUsername(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	// Create the first user via the service.
	if _, err := f.userSvc.Register(context.Background(), "dupuser", "first@example.com", "password123"); err != nil {
		t.Fatalf("register first user: %v", err)
	}

	// POST a second user with the same username but different email.
	form := url.Values{}
	form.Set("username", "dupuser")
	form.Set("email", "second@example.com")
	form.Set("password", "password456")
	form.Set("is_active", "on")

	rec := adminRequest(t, router, http.MethodPost, "/admin/users", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("duplicate username: got status %d, want 200 (re-render)", res.StatusCode)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "That username is already taken") {
		t.Errorf("duplicate username: response does not contain expected error message; got: %s", body)
	}

	// Only one user with that username should exist.
	users, err := f.userStore.List(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	count := 0
	for _, u := range users {
		if u.Username == "dupuser" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate username: expected 1 user with username 'dupuser', got %d", count)
	}
}

func TestAdminUsers_Create_DuplicateEmail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	// Create the first user via the service.
	if _, err := f.userSvc.Register(context.Background(), "emailuser1", "shared@example.com", "password123"); err != nil {
		t.Fatalf("register first user: %v", err)
	}

	// POST a second user with a different username but the same email.
	form := url.Values{}
	form.Set("username", "emailuser2")
	form.Set("email", "shared@example.com")
	form.Set("password", "password456")
	form.Set("is_active", "on")

	rec := adminRequest(t, router, http.MethodPost, "/admin/users", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("duplicate email: got status %d, want 200 (re-render)", res.StatusCode)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "An account with that email already exists") {
		t.Errorf("duplicate email: response does not contain expected error message; got: %s", body)
	}

	// Only one user with that email should exist.
	users, err := f.userStore.List(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	count := 0
	for _, u := range users {
		if u.Email == "shared@example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate email: expected 1 user with email 'shared@example.com', got %d", count)
	}
}

func TestAdminUsers_Create_MissingUsername(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	form := url.Values{}
	form.Set("username", "") // deliberately empty
	form.Set("email", "nouser@example.com")
	form.Set("password", "password123")
	form.Set("is_active", "on")

	rec := adminRequest(t, router, http.MethodPost, "/admin/users", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("missing username: got status %d, want 200 (re-render)", res.StatusCode)
	}

	body := rec.Body.String()
	// Handler renders a general "required" message when username is empty.
	if !strings.Contains(body, "required") {
		t.Errorf("missing username: response does not contain any error message; got: %s", body)
	}
}

// ─── PostCreateApp validation errors ─────────────────────────────────────────

func TestAdminApps_Create_MissingSlug(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	form := url.Values{}
	form.Set("slug", "") // deliberately empty
	form.Set("name", "Valid App Name")
	form.Set("is_active", "on")

	rec := adminRequest(t, router, http.MethodPost, "/admin/apps", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("missing slug: got status %d, want 200 (re-render)", res.StatusCode)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Slug and name are required") {
		t.Errorf("missing slug: response does not contain expected error message; got: %s", body)
	}
}

func TestAdminApps_Create_DuplicateSlug(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	// Create the first app via a successful POST.
	firstForm := url.Values{}
	firstForm.Set("slug", "my-app")
	firstForm.Set("name", "My App")
	firstForm.Set("is_active", "on")

	rec := adminRequest(t, router, http.MethodPost, "/admin/apps", token, f.cfg.Session.CookieName,
		strings.NewReader(firstForm.Encode()), "application/x-www-form-urlencoded")
	if rec.Result().StatusCode != http.StatusFound {
		t.Fatalf("create first app: unexpected status %d", rec.Result().StatusCode)
	}

	// POST a second app with the same slug but different name.
	secondForm := url.Values{}
	secondForm.Set("slug", "my-app")
	secondForm.Set("name", "Different App Name")
	secondForm.Set("is_active", "on")

	rec = adminRequest(t, router, http.MethodPost, "/admin/apps", token, f.cfg.Session.CookieName,
		strings.NewReader(secondForm.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("duplicate slug: got status %d, want 200 (re-render)", res.StatusCode)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "An app with that slug already exists") {
		t.Errorf("duplicate slug: response does not contain expected error message; got: %s", body)
	}
}

// ─── PostUpdateUser conflict ──────────────────────────────────────────────────

func TestAdminUsers_Update_DuplicateUsername(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	// Create two non-admin users.
	if _, err := f.userSvc.Register(ctx, "updateuser1", "updateuser1@example.com", "password123"); err != nil {
		t.Fatalf("register user1: %v", err)
	}
	user1, err := f.userStore.GetByUsername(ctx, "updateuser1")
	if err != nil {
		t.Fatalf("get user1: %v", err)
	}

	if _, err := f.userSvc.Register(ctx, "updateuser2", "updateuser2@example.com", "password123"); err != nil {
		t.Fatalf("register user2: %v", err)
	}
	user2, err := f.userStore.GetByUsername(ctx, "updateuser2")
	if err != nil {
		t.Fatalf("get user2: %v", err)
	}
	_ = user1 // user1 exists purely to occupy the username

	// Attempt to update user2's username to match user1's username.
	form := url.Values{}
	form.Set("username", "updateuser1") // conflict with user1
	form.Set("email", "updateuser2@example.com")
	form.Set("name", "User Two")
	form.Set("is_active", "on")

	rec := adminRequest(t, router, http.MethodPost, "/admin/users/"+user2.ID, token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("update duplicate username: got status %d, want 200 (re-render)", res.StatusCode)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "That username is already taken") {
		t.Errorf("update duplicate username: response does not contain expected error message; got: %s", body)
	}

	// Verify user2's username has NOT changed in the DB.
	refreshed, err := f.userStore.GetByID(ctx, user2.ID)
	if err != nil {
		t.Fatalf("get user2 after failed update: %v", err)
	}
	if refreshed.Username != "updateuser2" {
		t.Errorf("update duplicate username: user2 username changed to %q, expected it to remain %q", refreshed.Username, "updateuser2")
	}
}

// ─── Settings ────────────────────────────────────────────────────────────────

func TestAdminSettings_Update(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	router := buildAdminRouter(f)

	t.Run("get settings page", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/settings", token, f.cfg.Session.CookieName, nil, "")
		if rec.Result().StatusCode != http.StatusOK {
			t.Errorf("settings page: got %d, want 200", rec.Result().StatusCode)
		}
	})

	t.Run("post settings update", func(t *testing.T) {
		form := url.Values{}
		form.Set("allow_registration", "on") // checkbox on = true
		form.Set("session_duration_hours", "48")
		form.Set("smtp_from", "admin@example.com")

		rec := adminRequest(t, router, http.MethodPost, "/admin/settings", token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
		res := rec.Result()

		if res.StatusCode != http.StatusFound {
			t.Errorf("post settings: got %d, want 302", res.StatusCode)
		}

		// Verify the settings were saved.
		val, err := f.settings.Get(context.Background(), "allow_registration")
		if err != nil {
			t.Fatalf("get setting: %v", err)
		}
		if val != "true" {
			t.Errorf("allow_registration: got %q, want %q", val, "true")
		}

		val, err = f.settings.Get(context.Background(), "session_duration_hours")
		if err != nil {
			t.Fatalf("get session_duration_hours: %v", err)
		}
		if val != "48" {
			t.Errorf("session_duration_hours: got %q, want %q", val, "48")
		}
	})

	t.Run("post settings disable registration", func(t *testing.T) {
		form := url.Values{}
		// allow_registration checkbox absent = false
		form.Set("session_duration_hours", "24")

		rec := adminRequest(t, router, http.MethodPost, "/admin/settings", token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
		if rec.Result().StatusCode != http.StatusFound {
			t.Errorf("disable registration: got %d, want 302", rec.Result().StatusCode)
		}

		val, err := f.settings.Get(context.Background(), "allow_registration")
		if err != nil {
			t.Fatalf("get setting: %v", err)
		}
		if val != "false" {
			t.Errorf("allow_registration disabled: got %q, want %q", val, "false")
		}
	})

	t.Run("invalid session_duration_hours returns error", func(t *testing.T) {
		form := url.Values{}
		form.Set("allow_registration", "on")
		form.Set("session_duration_hours", "not-a-number")

		rec := adminRequest(t, router, http.MethodPost, "/admin/settings", token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
		res := rec.Result()

		// Should re-render (200) with an error flash, not redirect.
		if res.StatusCode != http.StatusOK {
			t.Errorf("invalid duration: got %d, want 200 (re-render)", res.StatusCode)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "positive number") {
			t.Errorf("invalid duration: response does not contain error message; got: %s", body)
		}
	})
}

// ─── OAuth credential management ─────────────────────────────────────────────

func TestAdminApps_OAuth(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	t.Run("generate credentials", func(t *testing.T) {
		a := &app.App{
			Slug:        "oauth-gen-app",
			Name:        "OAuth Gen App",
			HostPattern: "oauth-gen.example.com",
			IsActive:    true,
		}
		if err := f.appSvc.Create(ctx, a); err != nil {
			t.Fatalf("create app: %v", err)
		}
		created, err := f.appStore.GetBySlug(ctx, "oauth-gen-app")
		if err != nil {
			t.Fatalf("get app by slug: %v", err)
		}

		// POST to generate OAuth credentials.
		rec := adminRequest(t, router, http.MethodPost,
			"/admin/apps/"+created.ID+"/oauth/generate", token, f.cfg.Session.CookieName, nil, "")
		res := rec.Result()

		// Handler re-renders the form (200) with the secret shown once.
		if res.StatusCode != http.StatusOK {
			t.Errorf("generate oauth: got status %d, want 200", res.StatusCode)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Copy the secret") {
			t.Errorf("generate oauth: response does not contain copy-secret message; got: %s", body)
		}

		// The app must now have OAuthEnabled and a ClientID.
		updated, err := f.appStore.GetByID(ctx, created.ID)
		if err != nil {
			t.Fatalf("get updated app: %v", err)
		}
		if !updated.OAuthEnabled {
			t.Error("generate oauth: OAuthEnabled is false after generate")
		}
		if updated.ClientID == "" {
			t.Error("generate oauth: ClientID is empty after generate")
		}
		if updated.ClientSecretHash == "" {
			t.Error("generate oauth: ClientSecretHash is empty after generate")
		}
	})

	t.Run("generate credentials already enabled", func(t *testing.T) {
		a := &app.App{
			Slug:        "oauth-double-gen",
			Name:        "OAuth Double Gen",
			HostPattern: "oauth-double.example.com",
			IsActive:    true,
		}
		if err := f.appSvc.Create(ctx, a); err != nil {
			t.Fatalf("create app: %v", err)
		}
		created, err := f.appStore.GetBySlug(ctx, "oauth-double-gen")
		if err != nil {
			t.Fatalf("get app by slug: %v", err)
		}

		// First generate — must succeed.
		rec := adminRequest(t, router, http.MethodPost,
			"/admin/apps/"+created.ID+"/oauth/generate", token, f.cfg.Session.CookieName, nil, "")
		if rec.Result().StatusCode != http.StatusOK {
			t.Fatalf("first generate: unexpected status %d", rec.Result().StatusCode)
		}

		// Second generate — must render error flash.
		rec = adminRequest(t, router, http.MethodPost,
			"/admin/apps/"+created.ID+"/oauth/generate", token, f.cfg.Session.CookieName, nil, "")
		res := rec.Result()

		if res.StatusCode != http.StatusOK {
			t.Errorf("double generate: got status %d, want 200 (re-render with error)", res.StatusCode)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Failed to generate") {
			t.Errorf("double generate: response does not contain error message; got: %s", body)
		}
	})

	t.Run("rotate secret", func(t *testing.T) {
		a := &app.App{
			Slug:        "oauth-rotate-app",
			Name:        "OAuth Rotate App",
			HostPattern: "oauth-rotate.example.com",
			IsActive:    true,
		}
		if err := f.appSvc.Create(ctx, a); err != nil {
			t.Fatalf("create app: %v", err)
		}
		created, err := f.appStore.GetBySlug(ctx, "oauth-rotate-app")
		if err != nil {
			t.Fatalf("get app by slug: %v", err)
		}

		// Enable OAuth first.
		rec := adminRequest(t, router, http.MethodPost,
			"/admin/apps/"+created.ID+"/oauth/generate", token, f.cfg.Session.CookieName, nil, "")
		if rec.Result().StatusCode != http.StatusOK {
			t.Fatalf("generate: unexpected status %d", rec.Result().StatusCode)
		}

		// Capture the hash before rotation.
		beforeRotate, err := f.appStore.GetByID(ctx, created.ID)
		if err != nil {
			t.Fatalf("get app before rotate: %v", err)
		}
		oldHash := beforeRotate.ClientSecretHash

		// POST to rotate.
		rec = adminRequest(t, router, http.MethodPost,
			"/admin/apps/"+created.ID+"/oauth/rotate", token, f.cfg.Session.CookieName, nil, "")
		res := rec.Result()

		if res.StatusCode != http.StatusOK {
			t.Errorf("rotate: got status %d, want 200", res.StatusCode)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "rotated") {
			t.Errorf("rotate: response does not contain 'rotated'; got: %s", body)
		}

		// The hash must have changed.
		afterRotate, err := f.appStore.GetByID(ctx, created.ID)
		if err != nil {
			t.Fatalf("get app after rotate: %v", err)
		}
		if afterRotate.ClientSecretHash == oldHash {
			t.Error("rotate: ClientSecretHash did not change after rotation")
		}
	})

	t.Run("rotate secret not enabled", func(t *testing.T) {
		a := &app.App{
			Slug:        "oauth-rotate-disabled",
			Name:        "OAuth Rotate Disabled",
			HostPattern: "oauth-rotate-disabled.example.com",
			IsActive:    true,
		}
		if err := f.appSvc.Create(ctx, a); err != nil {
			t.Fatalf("create app: %v", err)
		}
		created, err := f.appStore.GetBySlug(ctx, "oauth-rotate-disabled")
		if err != nil {
			t.Fatalf("get app by slug: %v", err)
		}

		// POST rotate without ever enabling OAuth.
		rec := adminRequest(t, router, http.MethodPost,
			"/admin/apps/"+created.ID+"/oauth/rotate", token, f.cfg.Session.CookieName, nil, "")
		res := rec.Result()

		if res.StatusCode != http.StatusOK {
			t.Errorf("rotate not enabled: got status %d, want 200 (re-render with error)", res.StatusCode)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Failed to rotate") {
			t.Errorf("rotate not enabled: response does not contain error message; got: %s", body)
		}
	})

	t.Run("update redirect URIs", func(t *testing.T) {
		a := &app.App{
			Slug:        "redirect-uri-app",
			Name:        "Redirect URI App",
			HostPattern: "redirect-uri.example.com",
			IsActive:    true,
		}
		if err := f.appSvc.Create(ctx, a); err != nil {
			t.Fatalf("create app: %v", err)
		}
		created, err := f.appStore.GetBySlug(ctx, "redirect-uri-app")
		if err != nil {
			t.Fatalf("get app by slug: %v", err)
		}

		// POST update with redirect URIs.
		form := url.Values{}
		form.Set("slug", "redirect-uri-app")
		form.Set("name", "Redirect URI App")
		form.Set("host_pattern", "redirect-uri.example.com")
		form.Set("is_active", "on")
		form.Set("redirect_uris", "https://app.example.com/callback\nhttps://app.example.com/callback2\n")

		rec := adminRequest(t, router, http.MethodPost, "/admin/apps/"+created.ID, token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
		res := rec.Result()

		if res.StatusCode != http.StatusFound {
			t.Errorf("update redirect_uris: got %d, want 302", res.StatusCode)
		}

		// Verify the URIs were persisted.
		updated, err := f.appStore.GetByID(ctx, created.ID)
		if err != nil {
			t.Fatalf("get updated app: %v", err)
		}
		if len(updated.RedirectURIs) != 2 {
			t.Errorf("update redirect_uris: got %d URIs, want 2; uris: %v", len(updated.RedirectURIs), updated.RedirectURIs)
		}
		if len(updated.RedirectURIs) >= 1 && updated.RedirectURIs[0] != "https://app.example.com/callback" {
			t.Errorf("update redirect_uris: first URI = %q, want %q", updated.RedirectURIs[0], "https://app.example.com/callback")
		}
		if len(updated.RedirectURIs) >= 2 && updated.RedirectURIs[1] != "https://app.example.com/callback2" {
			t.Errorf("update redirect_uris: second URI = %q, want %q", updated.RedirectURIs[1], "https://app.example.com/callback2")
		}
	})
}
