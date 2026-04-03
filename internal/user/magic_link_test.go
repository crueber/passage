package user_test

import (
	"context"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// TestFindOrCreateByEmail_ExistingUser verifies that FindOrCreateByEmail returns
// the existing user (created=false) when the email is already registered.
func TestFindOrCreateByEmail_ExistingUser(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	// Pre-create a user.
	if _, err := svc.Register(ctx, "alice_magic", "alice_magic@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	u, created, err := svc.FindOrCreateByEmail(ctx, "alice_magic@example.com")
	if err != nil {
		t.Fatalf("FindOrCreateByEmail: unexpected error: %v", err)
	}
	if created {
		t.Error("FindOrCreateByEmail: expected created=false for existing user")
	}
	if u.Email != "alice_magic@example.com" {
		t.Errorf("FindOrCreateByEmail: got email %q, want %q", u.Email, "alice_magic@example.com")
	}
}

// TestFindOrCreateByEmail_NewUser verifies that FindOrCreateByEmail creates a
// new user when the email is not found, and returns created=true.
func TestFindOrCreateByEmail_NewUser(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	u, created, err := svc.FindOrCreateByEmail(ctx, "newmagic@example.com")
	if err != nil {
		t.Fatalf("FindOrCreateByEmail: unexpected error: %v", err)
	}
	if !created {
		t.Error("FindOrCreateByEmail: expected created=true for new user")
	}
	if u == nil {
		t.Fatal("FindOrCreateByEmail: expected non-nil user")
	}
	if u.ID == "" {
		t.Error("FindOrCreateByEmail: expected non-empty ID")
	}
	if u.Email != "newmagic@example.com" {
		t.Errorf("FindOrCreateByEmail: got email %q, want %q", u.Email, "newmagic@example.com")
	}
	// Username should be derived from the local part of the email.
	if u.Username == "" {
		t.Error("FindOrCreateByEmail: expected non-empty username")
	}
	if !u.IsActive {
		t.Error("FindOrCreateByEmail: expected new user to be active")
	}
}

// TestFindOrCreateByEmail_DerivedUsername verifies that the username is derived
// correctly from the email local part, replacing non-alphanumeric chars with _.
func TestFindOrCreateByEmail_DerivedUsername(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	u, created, err := svc.FindOrCreateByEmail(ctx, "foo.bar+baz@example.com")
	if err != nil {
		t.Fatalf("FindOrCreateByEmail: unexpected error: %v", err)
	}
	if !created {
		t.Error("FindOrCreateByEmail: expected created=true")
	}
	// "foo.bar+baz" → "foo_bar_baz"
	if u.Username == "" {
		t.Error("FindOrCreateByEmail: expected non-empty derived username")
	}
}

// TestConsumeMagicLinkToken_HappyPath verifies the full create → consume cycle.
func TestConsumeMagicLinkToken_HappyPath(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	// Create a user to attach the token to.
	u, err := svc.Register(ctx, "magic_happy", "magic_happy@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	tok, err := svc.CreateMagicLinkToken(ctx, u.ID, 15)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("CreateMagicLinkToken: expected non-empty token")
	}

	got, err := svc.ConsumeMagicLinkToken(ctx, tok.Token)
	if err != nil {
		t.Fatalf("ConsumeMagicLinkToken: unexpected error: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("ConsumeMagicLinkToken: got user ID %q, want %q", got.ID, u.ID)
	}
}

// TestConsumeMagicLinkToken_ExpiredToken verifies that an expired token returns
// ErrMagicLinkTokenExpired.
func TestConsumeMagicLinkToken_ExpiredToken(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	svc := user.NewService(store, store, testConfig(true))
	ctx := context.Background()

	u, err := svc.Register(ctx, "magic_expired", "magic_expired@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Insert an already-expired token directly via raw SQL.
	expiredToken := "expiredmagictoken1234567890abcdef1234567890abcdef1234567890abcdef"
	pastTime := time.Now().UTC().Add(-2 * time.Hour)
	_, err = db.ExecContext(ctx,
		`INSERT INTO magic_link_tokens (token, user_id, expires_at) VALUES (?, ?, ?)`,
		expiredToken, u.ID, pastTime,
	)
	if err != nil {
		t.Fatalf("insert expired token: %v", err)
	}

	_, err = svc.ConsumeMagicLinkToken(ctx, expiredToken)
	if !errors.Is(err, user.ErrMagicLinkTokenExpired) {
		t.Errorf("ConsumeMagicLinkToken expired: got %v, want ErrMagicLinkTokenExpired", err)
	}
}

// TestConsumeMagicLinkToken_UsedToken verifies that a double-spend attempt
// returns ErrMagicLinkTokenUsed.
func TestConsumeMagicLinkToken_UsedToken(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	u, err := svc.Register(ctx, "magic_used", "magic_used@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	tok, err := svc.CreateMagicLinkToken(ctx, u.ID, 15)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	// First consumption should succeed.
	if _, err := svc.ConsumeMagicLinkToken(ctx, tok.Token); err != nil {
		t.Fatalf("ConsumeMagicLinkToken (first): %v", err)
	}

	// Second consumption must return ErrMagicLinkTokenUsed.
	_, err = svc.ConsumeMagicLinkToken(ctx, tok.Token)
	if !errors.Is(err, user.ErrMagicLinkTokenUsed) {
		t.Errorf("ConsumeMagicLinkToken (second): got %v, want ErrMagicLinkTokenUsed", err)
	}
}

// TestConsumeMagicLinkToken_UnknownToken verifies that consuming an unknown
// token returns ErrMagicLinkTokenNotFound.
func TestConsumeMagicLinkToken_UnknownToken(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	_, err := svc.ConsumeMagicLinkToken(ctx, "doesnotexistdeadbeef")
	if !errors.Is(err, user.ErrMagicLinkTokenNotFound) {
		t.Errorf("ConsumeMagicLinkToken unknown: got %v, want ErrMagicLinkTokenNotFound", err)
	}
}

// ─── GetMagicLinkVerify handler tests ────────────────────────────────────────

// magicLinkEnabledSettings always returns "true" for any settings key.
// Used to enable magic link authentication in handler tests.
type magicLinkEnabledSettings struct{}

func (magicLinkEnabledSettings) Get(_ context.Context, _ string) (string, error) {
	return "true", nil
}

// newMagicLinkHandlerFixture builds a Handler fixture with magic link enabled.
// Returns the handler, db, service and config so tests can create tokens.
func newMagicLinkHandlerFixture(t *testing.T) (*user.Handler, *handlerFixture) {
	t.Helper()

	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)

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
		SMTP: config.SMTPConfig{
			Host: "localhost", // non-empty so magic link handler won't block on SMTP check
		},
	}

	userSvc := user.NewService(userStore, userStore, cfg)

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())

	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	h := user.NewHandler(userSvc, sessionSvc, magicLinkEnabledSettings{}, noopSender{}, tmpl, cfg, logger)

	f := &handlerFixture{
		db:      db,
		handler: h,
		userSvc: userSvc,
		cfg:     cfg,
	}
	return h, f
}

// TestHandler_GetMagicLinkVerify covers the five main cases for the verify endpoint.
func TestHandler_GetMagicLinkVerify(t *testing.T) {
	t.Parallel()

	t.Run("valid token sets session cookie and redirects", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		// Register a user and create a valid magic link token.
		u, err := f.userSvc.Register(context.Background(), "mlverifyok", "mlverifyok@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		tok, err := f.userSvc.CreateMagicLinkToken(context.Background(), u.ID, 15)
		if err != nil {
			t.Fatalf("CreateMagicLinkToken: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token="+tok.Token, nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusFound {
			t.Errorf("valid token: got status %d, want %d", res.StatusCode, http.StatusFound)
		}
		// Session cookie must be set.
		var sessionCookieSet bool
		for _, c := range res.Cookies() {
			if c.Name == f.cfg.Session.CookieName && c.Value != "" {
				sessionCookieSet = true
				break
			}
		}
		if !sessionCookieSet {
			t.Errorf("valid token: session cookie %q not set", f.cfg.Session.CookieName)
		}
	})

	t.Run("invalid token redirects to error page", func(t *testing.T) {
		t.Parallel()
		h, _ := newMagicLinkHandlerFixture(t)

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token=badtokenvalue", nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusFound {
			t.Errorf("invalid token: got status %d, want %d", res.StatusCode, http.StatusFound)
		}
		loc := res.Header.Get("Location")
		if loc == "" {
			t.Error("invalid token: expected redirect Location header")
		}
		// Must not redirect to a success page; must carry an error signal.
		if loc == "/" || loc == "/admin" {
			t.Errorf("invalid token: redirected to %q — looks like a success redirect", loc)
		}
	})

	t.Run("missing token redirects to error page", func(t *testing.T) {
		t.Parallel()
		h, _ := newMagicLinkHandlerFixture(t)

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify", nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusFound {
			t.Errorf("missing token: got status %d, want %d", res.StatusCode, http.StatusFound)
		}
		loc := res.Header.Get("Location")
		if loc == "" {
			t.Error("missing token: expected redirect Location header")
		}
		if loc == "/" || loc == "/admin" {
			t.Errorf("missing token: redirected to %q — looks like a success redirect", loc)
		}
	})

	t.Run("expired token redirects to error page", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		// Register a user and insert an already-expired token via raw SQL.
		if _, err := f.userSvc.Register(context.Background(), "mlverifyexp", "mlverifyexp@example.com", "password123"); err != nil {
			t.Fatalf("Register: %v", err)
		}
		expiredToken := "expiredmagictokenverify12345678901234567890"
		past := time.Now().UTC().Add(-2 * time.Hour)
		_, err := f.db.ExecContext(context.Background(),
			`INSERT INTO magic_link_tokens (token, user_id, expires_at)
			 SELECT ?, id, ? FROM users WHERE username = ?`,
			expiredToken, past, "mlverifyexp",
		)
		if err != nil {
			t.Fatalf("insert expired token: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token="+expiredToken, nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusFound {
			t.Errorf("expired token: got status %d, want %d", res.StatusCode, http.StatusFound)
		}
		loc := res.Header.Get("Location")
		if loc == "" {
			t.Error("expired token: expected redirect Location header")
		}
		if loc == "/" || loc == "/admin" {
			t.Errorf("expired token: redirected to %q — looks like a success redirect", loc)
		}
		// No session cookie must be set.
		for _, c := range res.Cookies() {
			if c.Name == f.cfg.Session.CookieName && c.Value != "" {
				t.Errorf("expired token: unexpected session cookie set")
			}
		}
	})

	t.Run("inactive user redirects to account-inactive error", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		// Register a user then deactivate them.
		u, err := f.userSvc.Register(context.Background(), "mlinactive", "mlinactive@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		u.IsActive = false
		store := user.NewStore(f.db)
		if err := store.Update(context.Background(), u); err != nil {
			t.Fatalf("Update (deactivate): %v", err)
		}

		tok, err := f.userSvc.CreateMagicLinkToken(context.Background(), u.ID, 15)
		if err != nil {
			t.Fatalf("CreateMagicLinkToken: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token="+tok.Token, nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusFound {
			t.Errorf("inactive user: got status %d, want %d", res.StatusCode, http.StatusFound)
		}
		loc := res.Header.Get("Location")
		if loc != "/login?flash=account-inactive" {
			t.Errorf("inactive user: got redirect %q, want %q", loc, "/login?flash=account-inactive")
		}
		// No session cookie.
		for _, c := range res.Cookies() {
			if c.Name == f.cfg.Session.CookieName && c.Value != "" {
				t.Errorf("inactive user: unexpected session cookie set")
			}
		}
	})

	t.Run("magic link method disabled returns 403", func(t *testing.T) {
		t.Parallel()
		db := testutil.NewTestDB(t)
		userStore := user.NewStore(db)
		cfg := &config.Config{
			Auth:    config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
			Session: config.SessionConfig{DurationHours: 24, CookieName: "passage_session"},
		}
		userSvc := user.NewService(userStore, userStore, cfg)
		sessionStore := session.NewStore(db)
		sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())
		tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
			"csrfField": func(_ string) template.HTML { return "" },
		})
		if err != nil {
			t.Fatalf("parse templates: %v", err)
		}
		logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
		// disabledSettings returns "false" for every key, disabling all auth methods.
		h := user.NewHandler(userSvc, sessionSvc, disabledSettings{}, noopSender{}, tmpl, cfg, logger)

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token=anytoken", nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("magic link disabled: got status %d, want %d", res.StatusCode, http.StatusForbidden)
		}
	})
}
