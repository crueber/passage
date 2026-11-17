package user_test

import (
	"context"
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

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/theme"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

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
	svc := user.NewService(store, store, nil, testConfig(true))
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

	userSvc := user.NewService(userStore, userStore, nil, cfg)

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())

	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme": func(data any) string {
			if v := web.ThemeFromData(data); v != "" {
				return v
			}
			return theme.Default()
		},
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	appStore := app.NewStore(db)
	authStore := authlog.NewStore(db)
	authRecorder := authlog.NewRecorder(authStore, nil, logger)

	// A real SQLite-backed per-address throttle with a clock the tests move by
	// hand, so a 24-hour block can be asserted without sleeping.
	magicClock := newTestClock()
	magicThrottle := ratelimit.NewMagicLinkService(
		ratelimit.NewMagicLinkStore(db),
		ratelimit.MagicLinkConfig{MaxFailures: 3, Window: 24 * time.Hour, Lockout: 24 * time.Hour},
		magicClock.Now,
	)
	mail := &recordingSender{}

	h := user.NewHandler(userSvc, nil, app.NewService(appStore, appStore, logger), sessionSvc, magicLinkEnabledSettings{}, mail, session.UserFromContext, authRecorder, nil, magicThrottle, tmpl, cfg, logger)

	f := &handlerFixture{
		db:            db,
		handler:       h,
		userSvc:       userSvc,
		userStore:     userStore,
		cfg:           cfg,
		authStore:     authStore,
		magicThrottle: magicThrottle,
		magicClock:    magicClock,
		magicMail:     mail,
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
		userSvc := user.NewService(userStore, userStore, nil, cfg)
		sessionStore := session.NewStore(db)
		sessionSvc := session.NewService(sessionStore, userStore, nil, nil, cfg, slog.Default())
		tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
			"csrfField": func(_ string) template.HTML { return "" },
			"theme": func(data any) string {
				if v := web.ThemeFromData(data); v != "" {
					return v
				}
				return theme.Default()
			},
		})
		if err != nil {
			t.Fatalf("parse templates: %v", err)
		}
		logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
		// disabledSettings returns "false" for every key, disabling all auth methods.
		appStore := app.NewStore(db)
		h := user.NewHandler(userSvc, nil, app.NewService(appStore, appStore, logger), sessionSvc, disabledSettings{}, noopSender{}, session.UserFromContext, nil, nil, nil, tmpl, cfg, logger)

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token=anytoken", nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("magic link disabled: got status %d, want %d", res.StatusCode, http.StatusForbidden)
		}
	})
}

// postMagicLink submits the request form from the given client address.
func postMagicLink(t *testing.T, h *user.Handler, email, ip string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"email": {email}}
	req := httptest.NewRequest(http.MethodPost, "/login/magic", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":54321"
	rec := httptest.NewRecorder()
	h.PostMagicLinkRequest(rec, req)
	return rec
}

// countUsers is the number of rows in users, used to prove a refused request
// never provisions an account.
func countUsers(t *testing.T, f *handlerFixture) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

// TestHandler_PostMagicLinkRequest covers the account gate, the shared
// response, and the per-address failure throttle. Every request ends on the
// same page: the response must not reveal whether an address is registered.
func TestHandler_PostMagicLinkRequest(t *testing.T) {
	t.Parallel()

	t.Run("existing account receives a link", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		if _, err := f.userSvc.Register(context.Background(), "mlknown", "mlknown@example.com", "password123"); err != nil {
			t.Fatalf("Register: %v", err)
		}

		rec := postMagicLink(t, h, "mlknown@example.com", "198.51.100.10")
		if body := rec.Body.String(); !strings.Contains(body, "If there&rsquo;s an account at that address") {
			t.Fatalf("existing account: expected the shared page, got %q", body)
		}
		if got := f.magicMail.sentMagicLinks(); len(got) != 1 || got[0] != "mlknown@example.com" {
			t.Fatalf("sent links = %v, want one to mlknown@example.com", got)
		}
	})

	t.Run("unknown account is indistinguishable and creates nothing", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		if _, err := f.userSvc.Register(context.Background(), "mlreal", "mlreal@example.com", "password123"); err != nil {
			t.Fatalf("Register: %v", err)
		}

		known := postMagicLink(t, h, "mlreal@example.com", "198.51.100.11").Body.String()
		unknown := postMagicLink(t, h, "nobody@example.com", "198.51.100.12").Body.String()
		if unknown != known {
			t.Errorf("unknown-account response differs from the known-account response:\nunknown: %q\nknown:   %q", unknown, known)
		}

		// Exactly one account exists, and only the real address was mailed.
		if n := countUsers(t, f); n != 1 {
			t.Errorf("users = %d, want 1 (a magic-link request must not provision)", n)
		}
		if got := f.magicMail.sentMagicLinks(); len(got) != 1 || got[0] != "mlreal@example.com" {
			t.Errorf("sent links = %v, want only mlreal@example.com", got)
		}
	})

	t.Run("three failed guesses block the address for 24 hours", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)
		if _, err := f.userSvc.Register(context.Background(), "mlblocked", "mlblocked@example.com", "password123"); err != nil {
			t.Fatalf("Register: %v", err)
		}

		const ip = "198.51.100.13"
		var first string
		for i := 1; i <= 3; i++ {
			body := postMagicLink(t, h, fmt.Sprintf("guess%d@example.com", i), ip).Body.String()
			if i == 1 {
				first = body
			}
			if body != first {
				t.Fatalf("guess %d: response changed while probing; want a constant page", i)
			}
		}

		// The address is blocked now: even a real account is answered with the
		// same page, and nothing is sent.
		rec := postMagicLink(t, h, "mlblocked@example.com", ip)
		if body := rec.Body.String(); body != first {
			t.Errorf("blocked address: response changed; want the shared page")
		}
		if got := f.magicMail.sentMagicLinks(); len(got) != 0 {
			t.Errorf("blocked address sent %v; want nothing", got)
		}

		// A different address is unaffected and still gets its link.
		other := postMagicLink(t, h, "mlblocked@example.com", "198.51.100.14")
		if body := other.Body.String(); body != first {
			t.Errorf("other address: response changed; want the shared page")
		}
		if got := f.magicMail.sentMagicLinks(); len(got) != 1 || got[0] != "mlblocked@example.com" {
			t.Errorf("other address sent %v, want one to mlblocked@example.com", got)
		}
	})

	t.Run("the block lifts after 24 hours", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)
		if _, err := f.userSvc.Register(context.Background(), "mlafter", "mlafter@example.com", "password123"); err != nil {
			t.Fatalf("Register: %v", err)
		}

		const ip = "198.51.100.15"
		for i := 1; i <= 3; i++ {
			postMagicLink(t, h, fmt.Sprintf("late%d@example.com", i), ip)
		}
		blocked := postMagicLink(t, h, "mlafter@example.com", ip).Body.String()
		if got := f.magicMail.sentMagicLinks(); len(got) != 0 {
			t.Fatalf("blocked address sent %v; want nothing", got)
		}
		if body := postMagicLink(t, h, "mlafter@example.com", ip).Body.String(); body != blocked {
			t.Fatalf("blocked response is not the shared page")
		}

		f.magicClock.Advance(24*time.Hour + time.Second)

		rec := postMagicLink(t, h, "mlafter@example.com", ip)
		if body := rec.Body.String(); body != blocked {
			t.Errorf("after the block expired: response changed; want the shared page")
		}
		if got := f.magicMail.sentMagicLinks(); len(got) != 1 || got[0] != "mlafter@example.com" {
			t.Errorf("after the block expired sent links = %v, want one to mlafter@example.com", got)
		}
	})
}
