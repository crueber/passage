package webauthn_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
	"github.com/crueber/passage/internal/webauthn"
)

type handlerFixture struct {
	userStore    *user.SQLiteStore
	userSvc      *user.Service
	sessionStore *session.SQLiteStore
	sessionSvc   *session.Service
	credStore    *webauthn.SQLiteCredentialStore
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
	userSvc := user.NewService(userStore, userStore, cfg)
	sessionStore := session.NewStore(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	sessionSvc := session.NewService(sessionStore, userStore, cfg, logger)
	credStore := webauthn.NewSQLiteCredentialStore(db)
	challenges := webauthn.NewChallengeStore()

	tmpl, err := web.Parse(web.TemplateFS)
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

	h := webauthn.NewHandler(wa, credStore, challenges, userStore, sessionSvc,
		cfg.Session.CookieName, cfg.Session.CookieSecure, tmpl, logger)

	return &handlerFixture{
		userStore:    userStore,
		userSvc:      userSvc,
		sessionStore: sessionStore,
		sessionSvc:   sessionSvc,
		credStore:    credStore,
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
