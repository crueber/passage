package webauthn_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/theme"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
	"github.com/crueber/passage/internal/webauthn"
)

type handlerFixture struct {
	db           *sql.DB
	userStore    *user.SQLiteStore
	userSvc      *user.Service
	sessionStore *session.SQLiteStore
	sessionSvc   *session.Service
	credStore    *webauthn.SQLiteCredentialStore
	mfaSvc       *mfa.Service
	cfg          *config.Config
	handler      *webauthn.Handler
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	db := testutil.NewTestDB(t)

	cfg := &config.Config{
		Auth:    config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{DurationHours: 24, CookieName: "passage_session", CookieSecure: false},
		Server:  config.ServerConfig{BaseURL: "http://localhost:8080"},
	}

	userStore := user.NewStore(db)
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	sessionStore := session.NewStore(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, logger)
	credStore := webauthn.NewSQLiteCredentialStore(db)
	challenges := webauthn.NewChallengeStore()

	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPDisplayName: "Passage Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	})
	if err != nil {
		t.Fatalf("create webauthn: %v", err)
	}

	mfaSvc := mfa.NewService(mfa.NewStore(db), "Passage", nil)
	h := webauthn.NewHandler(wa, credStore, challenges, userStore, sessionSvc,
		cfg.Session.CookieName, cfg.Session.CookieSecure, tmpl, logger, nil, nil, mfaSvc)

	return &handlerFixture{
		db:           db,
		userStore:    userStore,
		userSvc:      userSvc,
		sessionStore: sessionStore,
		sessionSvc:   sessionSvc,
		credStore:    credStore,
		mfaSvc:       mfaSvc,
		cfg:          cfg,
		handler:      h,
	}
}

func buildPasskeyRouter(f *handlerFixture) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(session.RequireSession(f.sessionSvc, f.cfg))
		f.handler.ProfileRoutes(r)
	})
	f.handler.AuthRoutes(r)
	return r
}

func TestGetPasskeys_RequiresSession(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	router := buildPasskeyRouter(f)

	req := httptest.NewRequest(http.MethodGet, "/passkeys", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusFound {
		t.Errorf("got %d, want 302", rec.Result().StatusCode)
	}
	if loc := rec.Result().Header.Get("Location"); loc == "" {
		t.Error("expected redirect Location header")
	}
}

func TestPostDeletePasskey_OwnershipCheck(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)

	// Create two users.
	_, err := f.userSvc.Register(context.Background(), "owner", "owner@example.com", "password123")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	owner, err := f.userStore.GetByUsername(context.Background(), "owner")
	if err != nil {
		t.Fatalf("get owner: %v", err)
	}

	_, err = f.userSvc.Register(context.Background(), "attacker", "attacker@example.com", "password123")
	if err != nil {
		t.Fatalf("register attacker: %v", err)
	}
	attacker, err := f.userStore.GetByUsername(context.Background(), "attacker")
	if err != nil {
		t.Fatalf("get attacker: %v", err)
	}

	// Create a credential belonging to owner.
	cred := &webauthn.Credential{
		ID:        "owner-cred-1",
		UserID:    owner.ID,
		Name:      "Owner's passkey",
		PublicKey: []byte(`{"ID":"owner-cred-1"}`),
		SignCount: 0,
	}
	if err := f.credStore.Create(context.Background(), cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	// Attacker creates a session.
	attackerToken, _, err := f.sessionSvc.CreateSession(context.Background(), attacker.ID, nil, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("create attacker session: %v", err)
	}

	router := buildPasskeyRouter(f)
	req := httptest.NewRequest(http.MethodPost, "/passkeys/delete/owner-cred-1", nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: attackerToken})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Should redirect (302), but NOT delete the credential.
	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("got %d, want 302", res.StatusCode)
	}

	// Credential must still exist.
	got, err := f.credStore.GetByID(context.Background(), "owner-cred-1")
	if err != nil {
		t.Fatalf("credential should still exist: %v", err)
	}
	if got.UserID != owner.ID {
		t.Errorf("credential owner changed: got %q, want %q", got.UserID, owner.ID)
	}
}

func TestPostDeletePasskey_Success(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)

	_, err := f.userSvc.Register(context.Background(), "delowner", "delowner@example.com", "password123")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	u, err := f.userStore.GetByUsername(context.Background(), "delowner")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	cred := &webauthn.Credential{
		ID:        "del-cred-1",
		UserID:    u.ID,
		Name:      "To be deleted",
		PublicKey: []byte(`{"ID":"del-cred-1"}`),
		SignCount: 0,
	}
	if err := f.credStore.Create(context.Background(), cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	token, _, err := f.sessionSvc.CreateSession(context.Background(), u.ID, nil, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	router := buildPasskeyRouter(f)
	req := httptest.NewRequest(http.MethodPost, "/passkeys/delete/del-cred-1", nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("got %d, want 302", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if loc != "/passkeys?flash=deleted" {
		t.Errorf("redirect: got %q, want %q", loc, "/passkeys?flash=deleted")
	}

	// Credential must be gone.
	_, err = f.credStore.GetByID(context.Background(), "del-cred-1")
	if err == nil {
		t.Error("credential should be deleted but still exists")
	}
}

// TestGetPasskeys_AuthenticatedEmpty verifies that a logged-in user with no
// registered passkeys receives the passkeys page (200) showing the empty state.
func TestGetPasskeys_AuthenticatedEmpty(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)

	_, err := f.userSvc.Register(context.Background(), "emptyuser", "emptyuser@example.com", "password123")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	u, err := f.userStore.GetByUsername(context.Background(), "emptyuser")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	token, _, err := f.sessionSvc.CreateSession(context.Background(), u.ID, nil, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	router := buildPasskeyRouter(f)
	req := httptest.NewRequest(http.MethodGet, "/passkeys", nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("got %d, want 200", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)

	// Must not be a redirect page.
	if strings.Contains(bodyStr, "Sign in") {
		t.Error("response body contains 'Sign in' — looks like a redirect/login page")
	}

	// The empty state from passkeys.html.
	const wantText = "You have no passkeys registered yet."
	if !strings.Contains(bodyStr, wantText) {
		t.Errorf("response body does not contain %q", wantText)
	}
}

// TestGetBeginRegistration_RequiresSession verifies that the begin-registration
// endpoint redirects unauthenticated requests to /login.
func TestGetBeginRegistration_RequiresSession(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	router := buildPasskeyRouter(f)

	req := httptest.NewRequest(http.MethodGet, "/passkeys/register/begin", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("got %d, want 302", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

// TestGetBeginRegistration_ReturnsJSON verifies that an authenticated user
// receives JSON credential-creation options and a wa_reg_session cookie.
func TestGetBeginRegistration_ReturnsJSON(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)

	_, err := f.userSvc.Register(context.Background(), "reguser", "reguser@example.com", "password123")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	u, err := f.userStore.GetByUsername(context.Background(), "reguser")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	token, _, err := f.sessionSvc.CreateSession(context.Background(), u.ID, nil, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	router := buildPasskeyRouter(f)
	req := httptest.NewRequest(http.MethodGet, "/passkeys/register/begin", nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("got %d, want 200", res.StatusCode)
	}

	ct := res.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !json.Valid(body) {
		t.Errorf("response body is not valid JSON: %s", body)
	}

	var foundRegCookie bool
	for _, c := range res.Cookies() {
		if c.Name == "wa_reg_session" {
			foundRegCookie = true
			break
		}
	}
	if !foundRegCookie {
		t.Error("expected wa_reg_session cookie to be set in response")
	}
}

// TestGetBeginLogin_ReturnsJSON verifies that the public begin-login endpoint
// returns JSON discoverable-login options and a wa_auth_session cookie.
// No session is required for this endpoint.
func TestGetBeginLogin_ReturnsJSON(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	router := buildPasskeyRouter(f)

	req := httptest.NewRequest(http.MethodPost, "/login/passkey/begin", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("got %d, want 200", res.StatusCode)
	}

	ct := res.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !json.Valid(body) {
		t.Errorf("response body is not valid JSON: %s", body)
	}

	var foundAuthCookie bool
	for _, c := range res.Cookies() {
		if c.Name == "wa_auth_session" {
			foundAuthCookie = true
			break
		}
	}
	if !foundAuthCookie {
		t.Error("expected wa_auth_session cookie to be set in response")
	}
}

// ─── fakes for PostFinishRegistration name tests ──────────────────────────────

// fakeWebAuthn implements the webAuthnCeremony interface (unexported, satisfied
// structurally) for use in PostFinishRegistration name tests.
// FinishRegistration always succeeds and returns a minimal credential with ID = [1].
type fakeWebAuthn struct{}

func (fakeWebAuthn) BeginRegistration(u gowebauthn.User, opts ...gowebauthn.RegistrationOption) (*protocol.CredentialCreation, *gowebauthn.SessionData, error) {
	return nil, nil, errors.New("not implemented in fake")
}

func (fakeWebAuthn) FinishRegistration(u gowebauthn.User, session gowebauthn.SessionData, r *http.Request) (*gowebauthn.Credential, error) {
	return &gowebauthn.Credential{
		ID:        []byte{1},
		PublicKey: []byte(`{}`),
	}, nil
}

func (fakeWebAuthn) BeginLogin(gowebauthn.User, ...gowebauthn.LoginOption) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	return nil, nil, errors.New("not implemented in fake")
}

func (fakeWebAuthn) FinishLogin(gowebauthn.User, gowebauthn.SessionData, *http.Request) (*gowebauthn.Credential, error) {
	return nil, errors.New("not implemented in fake")
}

func (fakeWebAuthn) BeginDiscoverableLogin(opts ...gowebauthn.LoginOption) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	return nil, nil, errors.New("not implemented in fake")
}

func (fakeWebAuthn) FinishPasskeyLogin(handler gowebauthn.DiscoverableUserHandler, session gowebauthn.SessionData, r *http.Request) (gowebauthn.User, *gowebauthn.Credential, error) {
	return nil, nil, errors.New("not implemented in fake")
}

// capturingCredStore implements CredentialStore; it captures the credential
// passed to Create and delegates reads to an embedded SQLiteCredentialStore.
type capturingCredStore struct {
	*webauthn.SQLiteCredentialStore
	created *webauthn.Credential
}

func (s *capturingCredStore) Create(ctx context.Context, cred *webauthn.Credential) error {
	s.created = cred
	return s.SQLiteCredentialStore.Create(ctx, cred)
}

// newFinishRegistrationFixture sets up a handlerFixture and a capturingCredStore
// so subtests can assert on what Name was stored. Each subtest builds its own
// Handler with a fresh ChallengeStore; this fixture deliberately does NOT
// construct a Handler to avoid dead code.
func newFinishRegistrationFixture(t *testing.T) (*handlerFixture, *capturingCredStore) {
	t.Helper()
	f := newHandlerFixture(t)

	capturing := &capturingCredStore{
		SQLiteCredentialStore: f.credStore,
	}

	return f, capturing
}

// seedRegistrationSession pre-loads a fake registration challenge and sets the
// wa_reg_session cookie on the request so PostFinishRegistration finds a session.
func seedRegistrationSession(t *testing.T, req *http.Request, challenges *webauthn.ChallengeStore) {
	t.Helper()
	sessionID := "test-session-id"
	challenges.SetRegistration(sessionID, gowebauthn.SessionData{})
	req.AddCookie(&http.Cookie{Name: "wa_reg_session", Value: sessionID})
}

// TestPostFinishRegistration_Name verifies that the stored credential Name
// reflects the ?name= query parameter, handles the empty case, and truncates
// names longer than 64 characters.
func TestPostFinishRegistration_Name(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		query    string
		wantName string
	}{
		{
			name:     "with name",
			query:    "?name=MyKey",
			wantName: "MyKey",
		},
		{
			name:     "without name",
			query:    "",
			wantName: "",
		},
		{
			name:     "name truncation",
			query:    "?name=" + strings.Repeat("a", 65),
			wantName: strings.Repeat("a", 64),
		},
		{
			name:     "name truncation multibyte",
			query:    "?name=" + url.QueryEscape(strings.Repeat("あ", 65)),
			wantName: strings.Repeat("あ", 64),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, capturing := newFinishRegistrationFixture(t)

			// Register a user and create a session.
			_, err := f.userSvc.Register(context.Background(), "finuser-"+tc.name, "finuser@example.com", "password123")
			if err != nil {
				t.Fatalf("register user: %v", err)
			}
			u, err := f.userStore.GetByUsername(context.Background(), "finuser-"+tc.name)
			if err != nil {
				t.Fatalf("get user: %v", err)
			}
			token, _, err := f.sessionSvc.CreateSession(context.Background(), u.ID, nil, "127.0.0.1", "test")
			if err != nil {
				t.Fatalf("create session: %v", err)
			}

			challenges := webauthn.NewChallengeStore()

			// Build a handler with this specific challenge store.
			tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
				"csrfField": func(_ string) template.HTML { return "" },
				"theme":     func() string { return theme.Default() },
			})
			if err != nil {
				t.Fatalf("parse templates: %v", err)
			}
			logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
			h := webauthn.NewHandler(
				fakeWebAuthn{},
				capturing,
				challenges,
				f.userStore,
				f.sessionSvc,
				f.cfg.Session.CookieName,
				f.cfg.Session.CookieSecure,
				tmpl,
				logger,
				nil,
				nil,
				nil,
			)

			router := chi.NewRouter()
			router.Group(func(r chi.Router) {
				r.Use(session.RequireSession(f.sessionSvc, f.cfg))
				h.ProfileRoutes(r)
			})

			req := httptest.NewRequest(http.MethodPost, "/passkeys/register/finish"+tc.query, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: token})
			seedRegistrationSession(t, req, challenges)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			res := rec.Result()
			if res.StatusCode != http.StatusCreated {
				body, _ := io.ReadAll(res.Body)
				t.Fatalf("got %d, want 201; body: %s", res.StatusCode, body)
			}

			if capturing.created == nil {
				t.Fatal("expected credential to be stored, but Create was never called")
			}
			if capturing.created.Name != tc.wantName {
				t.Errorf("credential Name: got %q, want %q", capturing.created.Name, tc.wantName)
			}
		})
	}
}

// ─── Auth method flag tests ───────────────────────────────────────────────────

// disabledPasskeySettings is a test-only passkeySettingsReader that always
// returns "false" — simulating the passkey auth method being disabled.
type disabledPasskeySettings struct{}

func (disabledPasskeySettings) Get(_ context.Context, _ string) (string, error) {
	return "false", nil
}

// TestGetBeginLogin_PasskeyDisabled verifies that GetBeginLogin returns 403 JSON
// when the auth_passkey_enabled setting is "false".
func TestGetBeginLogin_PasskeyDisabled(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)

	// Build a webauthn fixture with passkey disabled.
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPDisplayName: "Passage Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	})
	if err != nil {
		t.Fatalf("create webauthn: %v", err)
	}
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	challenges := webauthn.NewChallengeStore()
	h := webauthn.NewHandler(wa, f.credStore, challenges, f.userStore, f.sessionSvc,
		f.cfg.Session.CookieName, f.cfg.Session.CookieSecure, tmpl, logger, disabledPasskeySettings{}, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/login/passkey/begin", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.GetBeginLogin(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("GetBeginLogin with passkey disabled: got status %d, want %d", res.StatusCode, http.StatusForbidden)
	}
	ct := res.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("GetBeginLogin with passkey disabled: Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["error"] == "" {
		t.Errorf("GetBeginLogin with passkey disabled: missing error field in JSON response")
	}
}

// TestGetPasskeys_ShowsTwoFactorSection renders the Security page in both
// states. The enabled half is inserted straight into the store so the test
// exercises template execution (including the formatted date) without needing
// to derive a TOTP code here.
func TestGetPasskeys_ShowsTwoFactorSection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("disabled offers enrollment", func(t *testing.T) {
		t.Parallel()
		f := newHandlerFixture(t)
		if _, err := f.userSvc.Register(ctx, "plain", "plain@example.com", "password123"); err != nil {
			t.Fatalf("register: %v", err)
		}
		u, err := f.userStore.GetByUsername(ctx, "plain")
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		token, _, err := f.sessionSvc.CreateSession(ctx, u.ID, nil, "127.0.0.1", "test")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		rec := getPasskeysPage(t, f, token)
		body := rec.Body.String()
		for _, want := range []string{
			"Two-factor authentication",
			"Set up two-factor",
			`href="/mfa/setup"`,
			"<title>Security — Passage</title>",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("disabled state missing %q", want)
			}
		}
		if strings.Contains(body, "Enabled since") {
			t.Error("disabled state renders the enabled block")
		}
	})

	t.Run("enabled shows status and actions", func(t *testing.T) {
		t.Parallel()
		f := newHandlerFixture(t)
		if _, err := f.userSvc.Register(ctx, "secure", "secure@example.com", "password123"); err != nil {
			t.Fatalf("register: %v", err)
		}
		u, err := f.userStore.GetByUsername(ctx, "secure")
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		if _, err := f.db.ExecContext(ctx,
			`INSERT INTO user_mfa (user_id, secret, enabled_at) VALUES (?, 'JBSWY3DPEHPK3PXP', ?)`,
			u.ID, time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)); err != nil {
			t.Fatalf("insert credential: %v", err)
		}
		for i := 0; i < 10; i++ {
			if _, err := f.db.ExecContext(ctx,
				`INSERT INTO user_mfa_recovery_codes (user_id, hash) VALUES (?, ?)`,
				u.ID, fmt.Sprintf("hash-%02d", i)); err != nil {
				t.Fatalf("insert recovery code: %v", err)
			}
		}
		token, _, err := f.sessionSvc.CreateSession(ctx, u.ID, nil, "127.0.0.1", "test")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		rec := getPasskeysPage(t, f, token)
		body := rec.Body.String()
		for _, want := range []string{
			"Enabled since",
			"2026-11-01",
			"10 of 10",
			`action="/mfa/recovery-codes"`,
			`action="/mfa/disable"`,
			`name="password"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("enabled state missing %q", want)
			}
		}
		if strings.Contains(body, "Set up two-factor") {
			t.Error("enabled state still offers enrollment")
		}
	})
}

// TestGetPasskeys_FlashCodes pins the MFA flash codes the Security page
// understands, so a typo in a redirect target cannot silently drop the message.
func TestGetPasskeys_FlashCodes(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	if _, err := f.userSvc.Register(context.Background(), "flashed", "flashed@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}
	u, err := f.userStore.GetByUsername(context.Background(), "flashed")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	token, _, err := f.sessionSvc.CreateSession(context.Background(), u.ID, nil, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	tests := []struct {
		code string
		want string
	}{
		{"mfa-enabled", "Two-factor authentication is on"},
		{"mfa-disabled", "Two-factor authentication is off"},
		{"mfa-codes-regenerated", "New recovery codes generated"},
		{"mfa-on", "already enabled"},
		{"mfa-required", "requires two-factor authentication"},
		{"mfa-password-invalid", "password was incorrect"},
		{"deleted", "Passkey removed"},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/passkeys?flash="+tt.code, nil)
			req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: token})
			rec := httptest.NewRecorder()
			buildPasskeyRouter(f).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; want 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tt.want) {
				t.Errorf("flash %q did not render %q", tt.code, tt.want)
			}
		})
	}
}

// getPasskeysPage performs GET /passkeys through the session middleware, which
// is what puts the user in the request context.
func getPasskeysPage(t *testing.T, f *handlerFixture, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/passkeys", nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: token})
	rec := httptest.NewRecorder()
	buildPasskeyRouter(f).ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("GET /passkeys status = %d; want 200", rec.Result().StatusCode)
	}
	return rec
}

// TestGetBeginRegistration_RequestsDiscoverableCredential pins the fix for
// passkeys that registered successfully and could never authenticate: the login
// page is username-less, so registration must ask for a resident credential.
func TestGetBeginRegistration_RequestsDiscoverableCredential(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)

	if _, err := f.userSvc.Register(context.Background(), "resident", "resident@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}
	u, err := f.userStore.GetByUsername(context.Background(), "resident")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	token, _, err := f.sessionSvc.CreateSession(context.Background(), u.ID, nil, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/passkeys/register/begin", nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: token})
	rec := httptest.NewRecorder()
	buildPasskeyRouter(f).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}

	var opts struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &opts); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	if got := opts.PublicKey.AuthenticatorSelection.ResidentKey; got != "required" {
		t.Errorf("residentKey = %q; want \"required\" (a passkey must be discoverable for username-less login)", got)
	}
	if got := opts.PublicKey.AuthenticatorSelection.UserVerification; got != "preferred" {
		t.Errorf("userVerification = %q; want \"preferred\"", got)
	}
}

// TestGetBeginLogin_UsernameAllowsNonDiscoverableCredentials covers the second
// half of the fix: with a username, the credentials are sent as
// allowCredentials, so a credential created before resident keys were required
// still works.
func TestGetBeginLogin_UsernameAllowsNonDiscoverableCredentials(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)

	if _, err := f.userSvc.Register(context.Background(), "legacy", "legacy@example.com", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}
	u, err := f.userStore.GetByUsername(context.Background(), "legacy")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	raw := gowebauthn.Credential{ID: []byte{1, 2, 3, 4}}
	pub, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	if err := f.credStore.Create(context.Background(), &webauthn.Credential{
		ID:        base64.RawURLEncoding.EncodeToString(raw.ID),
		UserID:    u.ID,
		PublicKey: pub,
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	assertAllowCredentials := func(t *testing.T, body []byte, want int) {
		t.Helper()
		var opts struct {
			PublicKey struct {
				AllowCredentials []struct {
					ID string `json:"id"`
				} `json:"allowCredentials"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(body, &opts); err != nil {
			t.Fatalf("decode options: %v", err)
		}
		if len(opts.PublicKey.AllowCredentials) != want {
			t.Errorf("allowCredentials = %d; want %d", len(opts.PublicKey.AllowCredentials), want)
		}
	}

	// Username given: allow-list the account's credentials.
	req := httptest.NewRequest(http.MethodPost, "/login/passkey/begin", strings.NewReader(`{"username":"legacy"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	buildPasskeyRouter(f).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("username begin status = %d; want 200: %s", rec.Code, rec.Body.String())
	}
	assertAllowCredentials(t, rec.Body.Bytes(), 1)

	// No username: the original discoverable ceremony (no allow-list).
	req = httptest.NewRequest(http.MethodPost, "/login/passkey/begin", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	buildPasskeyRouter(f).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discoverable begin status = %d; want 200", rec.Code)
	}
	assertAllowCredentials(t, rec.Body.Bytes(), 0)

	// Unknown account and account without credentials answer identically.
	req = httptest.NewRequest(http.MethodPost, "/login/passkey/begin", strings.NewReader(`{"username":"nobody"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	buildPasskeyRouter(f).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown user status = %d; want 400", rec.Code)
	}
}
