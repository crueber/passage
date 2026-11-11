package webauthn_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/webauthn"
)

// passkeyLoginStub is a webAuthnCeremony implementation whose login finish
// either succeeds with a fixed user or fails.
type passkeyLoginStub struct {
	user gowebauthn.User
	err  error
}

func (passkeyLoginStub) BeginRegistration(gowebauthn.User, ...gowebauthn.RegistrationOption) (*protocol.CredentialCreation, *gowebauthn.SessionData, error) {
	return nil, nil, errors.New("unused in this test")
}

func (passkeyLoginStub) FinishRegistration(gowebauthn.User, gowebauthn.SessionData, *http.Request) (*gowebauthn.Credential, error) {
	return nil, errors.New("unused in this test")
}

func (passkeyLoginStub) BeginLogin(gowebauthn.User, ...gowebauthn.LoginOption) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	return nil, nil, errors.New("unused in this test")
}

func (passkeyLoginStub) FinishLogin(gowebauthn.User, gowebauthn.SessionData, *http.Request) (*gowebauthn.Credential, error) {
	return nil, errors.New("unused in this test")
}

func (passkeyLoginStub) BeginDiscoverableLogin(...gowebauthn.LoginOption) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	return nil, nil, errors.New("unused in this test")
}

func (s passkeyLoginStub) FinishPasskeyLogin(gowebauthn.DiscoverableUserHandler, gowebauthn.SessionData, *http.Request) (gowebauthn.User, *gowebauthn.Credential, error) {
	if s.err != nil {
		return nil, nil, s.err
	}
	return s.user, &gowebauthn.Credential{ID: []byte{1}}, nil
}

func (passkeyLoginStub) BeginLogin(gowebauthn.User, ...gowebauthn.LoginOption) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	return nil, nil, errors.New("unused in this test")
}

func (passkeyLoginStub) FinishLogin(gowebauthn.User, gowebauthn.SessionData, *http.Request) (*gowebauthn.Credential, error) {
	return nil, errors.New("unused in this test")
}

// newPasskeyLoginHandler wires a handler whose finished ceremony is controlled
// by stub, and returns the auth event store for assertions.
func newPasskeyLoginHandler(t *testing.T, f *handlerFixture, stub passkeyLoginStub) (*webauthn.Handler, *authlog.Store) {
	t.Helper()

	challenges := webauthn.NewChallengeStore()
	challenges.SetAuthentication("auth-session-1", gowebauthn.SessionData{Challenge: "challenge"})

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	authStore := authlog.NewStore(f.db)

	h := webauthn.NewHandler(
		stub,
		f.credStore,
		challenges,
		f.userStore,
		f.sessionSvc,
		f.cfg.Session.CookieName,
		f.cfg.Session.CookieSecure,
		nil,
		logger,
		nil,
		authlog.NewRecorder(authStore, nil, logger),
		nil,
	)
	return h, authStore
}

// finishPasskeyLogin posts a finish request carrying the challenge cookie.
func finishPasskeyLogin(h *webauthn.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/login/passkey/finish", nil)
	req.AddCookie(&http.Cookie{Name: "wa_auth_session", Value: "auth-session-1"})
	req.RemoteAddr = "192.0.2.30:54321"
	req.Header.Set("User-Agent", "passkey-test-agent")
	rec := httptest.NewRecorder()
	h.PostFinishLogin(rec, req)
	return rec
}

func TestPostFinishLogin_RecordsAuthEvents(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f := newHandlerFixture(t)

		u, err := f.userSvc.Register(context.Background(), "passkey-user", "passkey-user@example.com", "password123")
		if err != nil {
			t.Fatalf("register user: %v", err)
		}

		h, store := newPasskeyLoginHandler(t, f, passkeyLoginStub{user: webauthn.NewWebAuthnUser(u, nil)})
		rec := finishPasskeyLogin(h)

		if rec.Code != http.StatusOK {
			t.Fatalf("PostFinishLogin status = %d, want %d", rec.Code, http.StatusOK)
		}

		events, err := store.List(context.Background(), authlog.Filter{})
		if err != nil {
			t.Fatalf("list auth events: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("got %d auth events, want 1", len(events))
		}
		e := events[0]
		if e.Event != authlog.EventPasskeyLogin || e.Outcome != authlog.OutcomeSuccess {
			t.Errorf("event = %q/%q, want %q/%q", e.Event, e.Outcome, authlog.EventPasskeyLogin, authlog.OutcomeSuccess)
		}
		if e.Username != "passkey-user" {
			t.Errorf("Username = %q, want %q", e.Username, "passkey-user")
		}
		if e.UserID != u.ID {
			t.Errorf("UserID = %q, want %q", e.UserID, u.ID)
		}
		if e.IP != "192.0.2.30" {
			t.Errorf("IP = %q, want %q", e.IP, "192.0.2.30")
		}
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		f := newHandlerFixture(t)

		h, store := newPasskeyLoginHandler(t, f, passkeyLoginStub{err: errors.New("bad assertion")})
		rec := finishPasskeyLogin(h)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("PostFinishLogin status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}

		events, err := store.List(context.Background(), authlog.Filter{})
		if err != nil {
			t.Fatalf("list auth events: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("got %d auth events, want 1", len(events))
		}
		e := events[0]
		if e.Event != authlog.EventPasskeyFailure || e.Outcome != authlog.OutcomeFailure {
			t.Errorf("event = %q/%q, want %q/%q", e.Event, e.Outcome, authlog.EventPasskeyFailure, authlog.OutcomeFailure)
		}
		if e.Username != "" {
			t.Errorf("Username = %q, want empty", e.Username)
		}
	})

	t.Run("expired challenge", func(t *testing.T) {
		t.Parallel()
		f := newHandlerFixture(t)

		h, store := newPasskeyLoginHandler(t, f, passkeyLoginStub{err: errors.New("unreachable")})

		req := httptest.NewRequest(http.MethodPost, "/login/passkey/finish", nil)
		req.AddCookie(&http.Cookie{Name: "wa_auth_session", Value: "not-a-known-challenge"})
		rec := httptest.NewRecorder()
		h.PostFinishLogin(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PostFinishLogin status = %d, want %d", rec.Code, http.StatusBadRequest)
		}

		events, err := store.List(context.Background(), authlog.Filter{})
		if err != nil {
			t.Fatalf("list auth events: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("got %d auth events, want 1", len(events))
		}
		if events[0].Event != authlog.EventPasskeyFailure || events[0].Detail != "challenge expired or not found" {
			t.Errorf("event = %q/%q, want failure with challenge detail", events[0].Event, events[0].Detail)
		}
	})
}
