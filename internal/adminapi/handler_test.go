package adminapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/adminapi"
	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// ─── fixture ─────────────────────────────────────────────────────────────────

// auditFake is an in-memory auditSource. It records the requested window so the
// page/limit handling can be asserted.
type auditFake struct {
	records []adminapi.AuditRecord
	lastLim int
	lastOff int
}

func (f *auditFake) ListAudit(_ context.Context, limit, offset int) ([]adminapi.AuditRecord, error) {
	f.lastLim = limit
	f.lastOff = offset
	if offset >= len(f.records) {
		return nil, nil
	}
	end := offset + limit
	if end > len(f.records) {
		end = len(f.records)
	}
	return f.records[offset:end], nil
}

type fixture struct {
	router     http.Handler
	tokens     *adminapi.Service
	users      *user.SQLiteStore
	apps       *app.SQLiteStore
	sessions   *session.SQLiteStore
	authEvents *authlog.Store
	audit      *auditFake
	user       *user.User
	app        *app.App
	session    *session.Session
	token      string
}

// newFixture seeds one user, one app, one session, one audit record, and one
// valid API token, then wires the production-shaped router.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	database := testutil.NewTestDB(t)
	userStore := user.NewStore(database)
	appStore := app.NewStore(database)
	sessionStore := session.NewStore(database)
	authStore := authlog.NewStore(database)
	tokens := adminapi.NewService(adminapi.NewStore(database), logger)

	u := &user.User{
		Username:     "alice",
		Email:        "alice@example.com",
		Name:         "Alice Example",
		PasswordHash: "$2a$10$bcrypt-hash-that-must-never-leak",
		IsAdmin:      true,
		IsActive:     true,
		Roles:        "[]",
	}
	if err := userStore.Create(ctx, u); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	a := &app.App{
		Slug:             "grafana",
		Name:             "Grafana",
		Description:      "Dashboards",
		HostPattern:      "grafana.example.com",
		DefaultURL:       "https://grafana.example.com",
		IsActive:         true,
		ClientID:         "public-client-id",
		ClientSecretHash: "$2a$10$client-secret-hash-that-must-never-leak",
		RedirectURIs:     []string{"https://grafana.example.com/oauth/callback"},
		OAuthEnabled:     true,
	}
	if err := appStore.Create(ctx, a); err != nil {
		t.Fatalf("seed app: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	sess := &session.Session{
		ID:        "session-bearer-token-that-must-never-leak",
		UserID:    u.ID,
		IPAddress: "192.0.2.10",
		UserAgent: "Mozilla/5.0 Test",
		CreatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
	}
	if err := sessionStore.Create(ctx, sess); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	auditSource := &auditFake{records: []adminapi.AuditRecord{
		{ID: "audit-1", ActorName: "admin", Action: "user.create", TargetType: "user",
			TargetID: u.ID, TargetName: "alice", IPAddress: "198.51.100.1", CreatedAt: now},
		{ID: "audit-2", ActorName: "admin", Action: "app.create", TargetType: "app",
			TargetID: a.ID, TargetName: "Grafana", IPAddress: "198.51.100.2", CreatedAt: now},
	}}

	recorder := authlog.NewRecorder(authStore, nil, logger)
	handler := adminapi.NewHandler(userStore, appStore, sessionStore, auditSource, logger)

	router := chi.NewRouter()
	router.Route("/api/v1", func(r chi.Router) {
		r.Use(adminapi.RequireToken(tokens, recorder, logger))
		handler.Routes(r)
	})

	plaintext, _, err := tokens.Create(ctx, "test")
	if err != nil {
		t.Fatalf("create api token: %v", err)
	}

	return &fixture{
		router:     router,
		tokens:     tokens,
		users:      userStore,
		apps:       appStore,
		sessions:   sessionStore,
		authEvents: authStore,
		audit:      auditSource,
		user:       u,
		app:        a,
		session:    sess,
		token:      plaintext,
	}
}

// get performs an authenticated GET and returns the recorder.
func (f *fixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return request(t, f.router, path, "Bearer "+f.token)
}

// request performs a GET with the given Authorization value (empty = none).
func request(t *testing.T, router http.Handler, path, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decode parses a JSON response body into v and fails the test on error.
func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return v
}

// ─── authentication ──────────────────────────────────────────────────────────

func TestHandler_AuthenticationFailures(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	revokedPlain, revokedToken, err := f.tokens.Create(context.Background(), "revoked")
	if err != nil {
		t.Fatalf("create revoked token: %v", err)
	}
	if _, err := f.tokens.Revoke(context.Background(), revokedToken.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	tests := []struct {
		name          string
		authorization string
	}{
		{"no header", ""},
		{"empty bearer", "Bearer"},
		{"bearer with no value", "Bearer   "},
		{"wrong scheme", "Basic " + f.token},
		{"no scheme", f.token},
		{"unknown token", "Bearer " + adminapi.TokenPrefix + strings.Repeat("A", 43)},
		{"revoked token", "Bearer " + revokedPlain},
		{"truncated token", "Bearer " + f.token[:len(f.token)-1]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, f.router, "/api/v1/whoami", tc.authorization)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want %q", got, "Bearer")
			}
			if got := rec.Body.String(); !strings.Contains(got, `"error"`) {
				t.Errorf("401 body = %q, want a JSON error envelope", got)
			}
		})
	}
}

func TestHandler_AuthFailureIsRecorded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)

	rec := request(t, f.router, "/api/v1/users", "Bearer "+adminapi.TokenPrefix+strings.Repeat("B", 43))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	events, err := f.authEvents.List(ctx, authlog.Filter{Event: authlog.EventAPIAuthFailure})
	if err != nil {
		t.Fatalf("list auth events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("api.auth_failure events = %d, want 1", len(events))
	}
	if events[0].Outcome != authlog.OutcomeFailure {
		t.Errorf("outcome = %q, want %q", events[0].Outcome, authlog.OutcomeFailure)
	}
	if strings.Contains(events[0].Detail, strings.Repeat("B", 43)) {
		t.Error("the rejected token was written to the security log")
	}
}

// ─── whoami ──────────────────────────────────────────────────────────────────

type whoamiBody struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Scope      string  `json:"scope"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}

func TestHandler_Whoami(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := f.get(t, "/api/v1/whoami")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	body := decode[whoamiBody](t, rec)
	if body.ID == "" {
		t.Error("whoami has no id")
	}
	if body.Name != "test" {
		t.Errorf("name = %q, want %q", body.Name, "test")
	}
	if body.Scope != "read-only" {
		t.Errorf("scope = %q, want read-only", body.Scope)
	}
	if _, err := time.Parse(time.RFC3339, body.CreatedAt); err != nil {
		t.Errorf("created_at %q is not RFC3339: %v", body.CreatedAt, err)
	}
	if body.LastUsedAt == nil {
		t.Fatal("last_used_at is null after an authenticated request")
	}
	if _, err := time.Parse(time.RFC3339, *body.LastUsedAt); err != nil {
		t.Errorf("last_used_at %q is not RFC3339: %v", *body.LastUsedAt, err)
	}
}

// ─── users ───────────────────────────────────────────────────────────────────

type userBody struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	IsAdmin       bool   `json:"is_admin"`
	IsActive      bool   `json:"is_active"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type usersBody struct {
	Users []userBody `json:"users"`
}

func TestHandler_Users(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := f.get(t, "/api/v1/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := decode[usersBody](t, rec)
	if len(body.Users) != 1 {
		t.Fatalf("users = %d, want 1", len(body.Users))
	}
	got := body.Users[0]
	if got.ID != f.user.ID || got.Username != "alice" || got.Email != "alice@example.com" {
		t.Errorf("user payload = %+v", got)
	}
	if !got.IsAdmin || !got.IsActive {
		t.Errorf("is_admin/is_active = %v/%v, want true/true", got.IsAdmin, got.IsActive)
	}
	if _, err := time.Parse(time.RFC3339, got.CreatedAt); err != nil {
		t.Errorf("created_at %q is not RFC3339: %v", got.CreatedAt, err)
	}

	assertNoSecrets(t, rec.Body.String())

	rec = f.get(t, "/api/v1/users/"+f.user.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want 200", rec.Code)
	}
	if single := decode[userBody](t, rec); single.ID != f.user.ID {
		t.Errorf("detail id = %q, want %q", single.ID, f.user.ID)
	}
	assertNoSecrets(t, rec.Body.String())

	rec = f.get(t, "/api/v1/users/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing user status = %d, want 404", rec.Code)
	}
	if got := decode[map[string]string](t, rec)["error"]; got == "" {
		t.Error("404 response has no error message")
	}
}

// ─── apps ────────────────────────────────────────────────────────────────────

type appBody struct {
	ID                   string `json:"id"`
	Slug                 string `json:"slug"`
	Name                 string `json:"name"`
	Description          string `json:"description"`
	HostPattern          string `json:"host_pattern"`
	DefaultURL           string `json:"default_url"`
	IsActive             bool   `json:"is_active"`
	SessionDurationHours int    `json:"session_duration_hours"`
	OAuthEnabled         bool   `json:"oauth_enabled"`
	ClientID             string `json:"client_id"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
}

type appsBody struct {
	Apps []appBody `json:"apps"`
}

func TestHandler_Apps(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := f.get(t, "/api/v1/apps")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := decode[appsBody](t, rec)
	if len(body.Apps) != 1 {
		t.Fatalf("apps = %d, want 1", len(body.Apps))
	}
	got := body.Apps[0]
	if got.ID != f.app.ID || got.Slug != "grafana" || got.Name != "Grafana" {
		t.Errorf("app payload = %+v", got)
	}
	if !got.IsActive || !got.OAuthEnabled {
		t.Errorf("is_active/oauth_enabled = %v/%v, want true/true", got.IsActive, got.OAuthEnabled)
	}
	if got.ClientID != "public-client-id" {
		t.Errorf("client_id = %q, want the public client id", got.ClientID)
	}
	if got.HostPattern != "grafana.example.com" {
		t.Errorf("host_pattern = %q", got.HostPattern)
	}
	assertNoSecrets(t, rec.Body.String())

	rec = f.get(t, "/api/v1/apps/"+f.app.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want 200", rec.Code)
	}
	if single := decode[appBody](t, rec); single.ID != f.app.ID {
		t.Errorf("detail id = %q, want %q", single.ID, f.app.ID)
	}
	assertNoSecrets(t, rec.Body.String())

	rec = f.get(t, "/api/v1/apps/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing app status = %d, want 404", rec.Code)
	}
}

// ─── sessions ────────────────────────────────────────────────────────────────

type sessionBody struct {
	PublicID   string  `json:"public_id"`
	UserID     string  `json:"user_id"`
	Username   string  `json:"username"`
	AppID      *string `json:"app_id"`
	IPAddress  string  `json:"ip_address"`
	UserAgent  string  `json:"user_agent"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	ExpiresAt  string  `json:"expires_at"`
}

type sessionsBody struct {
	Sessions []sessionBody `json:"sessions"`
}

func TestHandler_Sessions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// A second, app-scoped session proves app_id is emitted when set.
	appSession := &session.Session{
		ID:        "app-session-bearer-token",
		UserID:    f.user.ID,
		AppID:     &f.app.ID,
		IPAddress: "192.0.2.11",
		UserAgent: "Agent/2",
		CreatedAt: time.Now().UTC().Add(-time.Minute),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := f.sessions.Create(context.Background(), appSession); err != nil {
		t.Fatalf("seed app session: %v", err)
	}

	rec := f.get(t, "/api/v1/sessions")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := decode[sessionsBody](t, rec)
	if len(body.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(body.Sessions))
	}

	byUser := make(map[string]sessionBody)
	for _, s := range body.Sessions {
		byUser[s.IPAddress] = s
	}

	global, ok := byUser["192.0.2.10"]
	if !ok {
		t.Fatal("global session missing from the response")
	}
	if global.PublicID != f.session.PublicID {
		t.Errorf("public_id = %q, want %q", global.PublicID, f.session.PublicID)
	}
	if global.Username != "alice" {
		t.Errorf("username = %q, want alice", global.Username)
	}
	if global.AppID != nil {
		t.Errorf("app_id = %v, want null for a global session", *global.AppID)
	}
	if global.ExpiresAt == "" || global.CreatedAt == "" {
		t.Error("session timestamps are missing")
	}

	scoped, ok := byUser["192.0.2.11"]
	if !ok {
		t.Fatal("app session missing from the response")
	}
	if scoped.AppID == nil || *scoped.AppID != f.app.ID {
		t.Errorf("app_id = %v, want %q", scoped.AppID, f.app.ID)
	}

	raw := rec.Body.String()
	assertNoSecrets(t, raw)
	// The session ID is a bearer token and must never be serialised.
	for _, id := range []string{f.session.ID, appSession.ID} {
		if strings.Contains(raw, id) {
			t.Errorf("response contains a raw session ID %q", id)
		}
	}
}

// ─── audit ───────────────────────────────────────────────────────────────────

type auditEventBody struct {
	ID         string `json:"id"`
	ActorID    string `json:"actor_id"`
	ActorName  string `json:"actor_name"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	Detail     string `json:"detail"`
	IPAddress  string `json:"ip_address"`
	CreatedAt  string `json:"created_at"`
}

type auditBody struct {
	Events []auditEventBody `json:"events"`
	Page   int              `json:"page"`
	Limit  int              `json:"limit"`
}

func TestHandler_Audit(t *testing.T) {
	t.Parallel()

	t.Run("shape and defaults", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)

		rec := f.get(t, "/api/v1/audit")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		body := decode[auditBody](t, rec)
		if len(body.Events) != 2 {
			t.Fatalf("events = %d, want 2", len(body.Events))
		}
		if body.Page != 1 || body.Limit != 50 {
			t.Errorf("page/limit = %d/%d, want 1/50", body.Page, body.Limit)
		}
		got := body.Events[0]
		if got.ID != "audit-1" || got.Action != "user.create" || got.ActorName != "admin" {
			t.Errorf("event payload = %+v", got)
		}
		if got.TargetType != "user" || got.TargetName != "alice" || got.IPAddress != "198.51.100.1" {
			t.Errorf("event target/ip = %+v", got)
		}
		if _, err := time.Parse(time.RFC3339, got.CreatedAt); err != nil {
			t.Errorf("created_at %q is not RFC3339: %v", got.CreatedAt, err)
		}
	})

	t.Run("pagination", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)

		rec := f.get(t, "/api/v1/audit?page=2&limit=1")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if f.audit.lastLim != 1 || f.audit.lastOff != 1 {
			t.Errorf("adapter saw limit/offset %d/%d, want 1/1", f.audit.lastLim, f.audit.lastOff)
		}
		body := decode[auditBody](t, rec)
		if body.Page != 2 || body.Limit != 1 {
			t.Errorf("page/limit = %d/%d, want 2/1", body.Page, body.Limit)
		}
		if len(body.Events) != 1 || body.Events[0].ID != "audit-2" {
			t.Errorf("page 2 events = %+v, want audit-2", body.Events)
		}
	})

	t.Run("invalid and oversized values fall back safely", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)

		rec := f.get(t, "/api/v1/audit?page=abc&limit=-5")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if body := decode[auditBody](t, rec); body.Page != 1 || body.Limit != 50 {
			t.Errorf("page/limit = %d/%d, want defaults 1/50", body.Page, body.Limit)
		}

		rec = f.get(t, "/api/v1/audit?limit=100000")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if f.audit.lastLim != 500 {
			t.Errorf("limit passed to the store = %d, want the 500 cap", f.audit.lastLim)
		}
	})
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// assertNoSecrets fails if a response body contains a secret field name or a
// secret value from the seeded fixture.
func assertNoSecrets(t *testing.T, body string) {
	t.Helper()
	forbidden := []string{
		"password_hash",
		"client_secret_hash",
		"token_hash",
		"bcrypt-hash-that-must-never-leak",
		"client-secret-hash-that-must-never-leak",
		"session-bearer-token-that-must-never-leak",
	}
	for _, s := range forbidden {
		if strings.Contains(body, s) {
			t.Errorf("response contains secret %q: %s", s, truncate(body, 300))
		}
	}
}

// truncate shortens a body for error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return fmt.Sprintf("%s…", s[:n])
}
