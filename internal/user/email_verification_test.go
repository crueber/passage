package user_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// verificationEmail records one outbound verification message.
type verificationEmail struct {
	To   string
	Name string
	URL  string
}

// recordingSender is an email.Sender test double that records verification
// emails and can be made to fail, without touching SMTP.
type recordingSender struct {
	mu            sync.Mutex
	err           error
	verifications []verificationEmail
}

func (s *recordingSender) SendVerifyEmail(_ context.Context, to, name, url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.verifications = append(s.verifications, verificationEmail{To: to, Name: name, URL: url})
	return nil
}

func (s *recordingSender) SendPasswordReset(_ context.Context, _, _, _ string) error { return nil }
func (s *recordingSender) SendMagicLink(_ context.Context, _, _, _ string) error     { return nil }

// sent returns a copy of the recorded verification emails (race-safe).
func (s *recordingSender) sent() []verificationEmail {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]verificationEmail, len(s.verifications))
	copy(out, s.verifications)
	return out
}

// withSMTP configures a usable mail server and an absolute base URL.
func withSMTP(cfg *config.Config) {
	cfg.Server.BaseURL = "https://auth.example.com"
	cfg.SMTP = config.SMTPConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "passage@example.com",
		TLS:  "starttls",
	}
}

// ─── Token lifecycle (service) ───────────────────────────────────────────────

func TestEmailVerificationToken_Lifecycle(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	cfg := testConfig(true)
	withSMTP(cfg)
	svc := user.NewService(store, store, nil, cfg)
	ctx := context.Background()

	u, err := svc.Register(ctx, "verify_lifecycle", "verify_lifecycle@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.EmailVerified {
		t.Fatal("Register with SMTP configured: EmailVerified = true, want false")
	}

	tok, err := svc.CreateEmailVerificationToken(ctx, u.ID, u.Email)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}
	if len(tok.Token) != 64 {
		t.Errorf("token length = %d, want 64 hex chars (32 bytes)", len(tok.Token))
	}
	if !tok.ExpiresAt.After(time.Now().UTC()) {
		t.Errorf("expires_at = %v, want in the future", tok.ExpiresAt)
	}

	// First use verifies the account.
	verified, err := svc.ConsumeEmailVerificationToken(ctx, tok.Token)
	if err != nil {
		t.Fatalf("ConsumeEmailVerificationToken: %v", err)
	}
	if !verified.EmailVerified {
		t.Error("ConsumeEmailVerificationToken: returned user is not verified")
	}

	fresh, err := store.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !fresh.EmailVerified {
		t.Error("GetByID after consume: EmailVerified = false, want true")
	}
	// Verification must not disturb the credential material.
	if fresh.PasswordHash != u.PasswordHash {
		t.Error("consume changed password_hash")
	}

	// Replay is rejected.
	if _, err := svc.ConsumeEmailVerificationToken(ctx, tok.Token); !errors.Is(err, user.ErrEmailVerificationTokenUsed) {
		t.Errorf("replay: got %v, want ErrEmailVerificationTokenUsed", err)
	}

	// Unknown token is rejected.
	if _, err := svc.ConsumeEmailVerificationToken(ctx, "deadbeef"); !errors.Is(err, user.ErrEmailVerificationTokenNotFound) {
		t.Errorf("unknown token: got %v, want ErrEmailVerificationTokenNotFound", err)
	}
}

func TestEmailVerificationToken_ExpiryAndReissue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	cfg := testConfig(true)
	withSMTP(cfg)
	svc := user.NewService(store, store, nil, cfg)

	u, err := svc.Register(ctx, "verify_expiry", "verify_expiry@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	t.Run("expired token is rejected and does not verify", func(t *testing.T) {
		expired := "expiredverificationtoken0000000000000000000000000000000000000000000"
		_, err := db.ExecContext(ctx,
			`INSERT INTO email_verification_tokens (token, user_id, email, expires_at)
			 VALUES (?, ?, ?, ?)`,
			expired, u.ID, u.Email, time.Now().UTC().Add(-time.Minute),
		)
		if err != nil {
			t.Fatalf("insert expired token: %v", err)
		}

		if _, err := svc.ConsumeEmailVerificationToken(ctx, expired); !errors.Is(err, user.ErrEmailVerificationTokenExpired) {
			t.Errorf("expired token: got %v, want ErrEmailVerificationTokenExpired", err)
		}
		fresh, err := store.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if fresh.EmailVerified {
			t.Error("expired token verified the account; want it left unverified")
		}
	})

	t.Run("issuing a new token invalidates the previous unused one", func(t *testing.T) {
		first, err := svc.CreateEmailVerificationToken(ctx, u.ID, u.Email)
		if err != nil {
			t.Fatalf("create first token: %v", err)
		}
		second, err := svc.CreateEmailVerificationToken(ctx, u.ID, u.Email)
		if err != nil {
			t.Fatalf("create second token: %v", err)
		}

		if _, err := svc.ConsumeEmailVerificationToken(ctx, first.Token); !errors.Is(err, user.ErrEmailVerificationTokenNotFound) {
			t.Errorf("superseded token: got %v, want ErrEmailVerificationTokenNotFound", err)
		}
		if _, err := svc.ConsumeEmailVerificationToken(ctx, second.Token); err != nil {
			t.Errorf("newest token: unexpected error: %v", err)
		}
	})
}

// TestEmailVerificationToken_StaleAddressRejected proves a token mailed to an
// old address cannot verify an account whose address has since changed.
func TestEmailVerificationToken_StaleAddressRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	cfg := testConfig(true)
	withSMTP(cfg)
	svc := user.NewService(store, store, nil, cfg)

	u, err := svc.Register(ctx, "verify_stale", "old@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	tok, err := svc.CreateEmailVerificationToken(ctx, u.ID, u.Email)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	// Simulate an administrative address change after the link was sent.
	u.Email = "new@example.com"
	if err := store.Update(ctx, u); err != nil {
		t.Fatalf("Update email: %v", err)
	}

	if _, err := svc.ConsumeEmailVerificationToken(ctx, tok.Token); !errors.Is(err, user.ErrEmailVerificationTokenNotFound) {
		t.Errorf("stale address token: got %v, want ErrEmailVerificationTokenNotFound", err)
	}
	fresh, err := store.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if fresh.EmailVerified {
		t.Error("stale address token verified the account; want it left unverified")
	}
}

func TestService_Register_VerificationPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		smtp         bool
		wantVerified bool
	}{
		{name: "SMTP configured creates an unverified account", smtp: true, wantVerified: false},
		{name: "no SMTP auto-verifies", smtp: false, wantVerified: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := newUserService(t, true) // no SMTP in the default test config
			if tc.smtp {
				db := testutil.NewTestDB(t)
				store := user.NewStore(db)
				cfg := testConfig(true)
				withSMTP(cfg)
				svc = user.NewService(store, store, nil, cfg)
			}

			u, err := svc.Register(context.Background(), "policy", "policy@example.com", "password123")
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			if u.EmailVerified != tc.wantVerified {
				t.Errorf("EmailVerified = %v, want %v", u.EmailVerified, tc.wantVerified)
			}
			// Regardless of the flag, the account authenticates.
			if _, err := svc.Authenticate(context.Background(), "policy", "password123"); err != nil {
				t.Errorf("Authenticate after register: %v (verification must never block sign-in)", err)
			}
		})
	}
}

// ─── Registration handler ────────────────────────────────────────────────────

func TestHandler_PostRegister_EmailVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		mutate       func(*config.Config)
		sendErr      error
		wantVerified bool
		wantEmails   int
		wantTokens   int
	}{
		{
			name:         "SMTP configured: unverified plus one email",
			mutate:       withSMTP,
			wantVerified: false,
			wantEmails:   1,
			wantTokens:   1,
		},
		{
			name:         "no SMTP: auto-verified, no email, no token",
			mutate:       nil,
			wantVerified: true,
			wantEmails:   0,
			wantTokens:   0,
		},
		{
			name:         "send failure: still registers, stays unverified",
			mutate:       withSMTP,
			sendErr:      errors.New("smtp unreachable"),
			wantVerified: false,
			wantEmails:   0,
			wantTokens:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sender := &recordingSender{err: tc.sendErr}
			f := newFullHandlerFixtureWith(t, true, tc.mutate, sender)

			form := strings.NewReader("username=newuser&email=newuser@example.com&password=securepassword")
			req := httptest.NewRequest(http.MethodPost, "/register", form)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			f.handler.PostRegister(rec, req)

			res := rec.Result()
			if res.StatusCode != http.StatusFound {
				t.Fatalf("PostRegister: got status %d, want %d (a mail failure must not 500 the request)", res.StatusCode, http.StatusFound)
			}

			store := user.NewStore(f.db)
			u, err := store.GetByUsername(context.Background(), "newuser")
			if err != nil {
				t.Fatalf("GetByUsername: %v", err)
			}
			if u.EmailVerified != tc.wantVerified {
				t.Errorf("EmailVerified = %v, want %v", u.EmailVerified, tc.wantVerified)
			}

			emails := sender.sent()
			if len(emails) != tc.wantEmails {
				t.Fatalf("verification emails = %d, want %d", len(emails), tc.wantEmails)
			}
			for _, e := range emails {
				if e.To != "newuser@example.com" {
					t.Errorf("email sent to %q, want %q", e.To, "newuser@example.com")
				}
				if !strings.HasPrefix(e.URL, "https://auth.example.com/verify-email/") {
					t.Errorf("verification URL = %q, want prefix %q", e.URL, "https://auth.example.com/verify-email/")
				}
			}

			var tokens int
			if err := f.db.QueryRowContext(context.Background(),
				`SELECT COUNT(*) FROM email_verification_tokens WHERE user_id = ?`, u.ID,
			).Scan(&tokens); err != nil {
				t.Fatalf("count tokens: %v", err)
			}
			if tokens != tc.wantTokens {
				t.Errorf("verification tokens = %d, want %d", tokens, tc.wantTokens)
			}
		})
	}
}

// ─── GET /verify-email/{token} ───────────────────────────────────────────────

func TestHandler_GetVerifyEmail(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("valid token while signed in verifies and redirects to dashboard", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWith(t, true, withSMTP, noopSender{})
		u, err := f.userSvc.Register(ctx, "verify_happy", "verify_happy@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		tok, err := f.userSvc.CreateEmailVerificationToken(ctx, u.ID, u.Email)
		if err != nil {
			t.Fatalf("CreateEmailVerificationToken: %v", err)
		}

		req := withChiToken(httptest.NewRequest(http.MethodGet, "/verify-email/"+tok.Token, nil), tok.Token)
		req = req.WithContext(session.WithUser(req.Context(), u))
		rec := httptest.NewRecorder()
		f.handler.GetVerifyEmail(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusFound)
		}
		if loc := res.Header.Get("Location"); loc != "/?flash=email-verified" {
			t.Errorf("Location = %q, want %q", loc, "/?flash=email-verified")
		}
		fresh, err := user.NewStore(f.db).GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if !fresh.EmailVerified {
			t.Error("user still unverified after using a valid token")
		}
	})

	t.Run("valid token while signed out redirects to login with success flash", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWith(t, true, withSMTP, noopSender{})
		u, err := f.userSvc.Register(ctx, "verify_anon", "verify_anon@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		tok, err := f.userSvc.CreateEmailVerificationToken(ctx, u.ID, u.Email)
		if err != nil {
			t.Fatalf("CreateEmailVerificationToken: %v", err)
		}

		req := withChiToken(httptest.NewRequest(http.MethodGet, "/verify-email/"+tok.Token, nil), tok.Token)
		rec := httptest.NewRecorder()
		f.handler.GetVerifyEmail(rec, req)

		if loc := rec.Result().Header.Get("Location"); loc != "/login?flash=email-verified" {
			t.Errorf("Location = %q, want %q", loc, "/login?flash=email-verified")
		}
	})

	t.Run("valid token while a different account is signed in goes to login", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWith(t, true, withSMTP, noopSender{})
		owner, err := f.userSvc.Register(ctx, "verify_owner", "verify_owner@example.com", "password123")
		if err != nil {
			t.Fatalf("Register owner: %v", err)
		}
		other, err := f.userSvc.Register(ctx, "verify_other", "verify_other@example.com", "password123")
		if err != nil {
			t.Fatalf("Register other: %v", err)
		}
		tok, err := f.userSvc.CreateEmailVerificationToken(ctx, owner.ID, owner.Email)
		if err != nil {
			t.Fatalf("CreateEmailVerificationToken: %v", err)
		}

		req := withChiToken(httptest.NewRequest(http.MethodGet, "/verify-email/"+tok.Token, nil), tok.Token)
		req = req.WithContext(session.WithUser(req.Context(), other))
		rec := httptest.NewRecorder()
		f.handler.GetVerifyEmail(rec, req)

		// The owner is verified, but the signed-in account must not see the
		// owner's confirmation on its own dashboard.
		if loc := rec.Result().Header.Get("Location"); loc != "/login?flash=email-verified" {
			t.Errorf("Location = %q, want %q", loc, "/login?flash=email-verified")
		}
		fresh, err := user.NewStore(f.db).GetByID(ctx, owner.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if !fresh.EmailVerified {
			t.Error("owner still unverified after using a valid token")
		}
	})

	t.Run("invalid, expired, used, and missing tokens redirect without error", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWith(t, true, withSMTP, noopSender{})
		u, err := f.userSvc.Register(ctx, "verify_bad", "verify_bad@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		used, err := f.userSvc.CreateEmailVerificationToken(ctx, u.ID, u.Email)
		if err != nil {
			t.Fatalf("CreateEmailVerificationToken: %v", err)
		}
		if _, err := f.userSvc.ConsumeEmailVerificationToken(ctx, used.Token); err != nil {
			t.Fatalf("consume used token: %v", err)
		}

		expired := "expiredverificationhandler00000000000000000000000000000000000000000"
		if _, err := f.db.ExecContext(ctx,
			`INSERT INTO email_verification_tokens (token, user_id, email, expires_at)
			 VALUES (?, ?, ?, ?)`,
			expired, u.ID, u.Email, time.Now().UTC().Add(-time.Minute),
		); err != nil {
			t.Fatalf("insert expired token: %v", err)
		}

		tests := []struct {
			name    string
			token   string
			wantLoc string
		}{
			{"used token", used.Token, "/login?flash=verify-link-used"},
			{"expired token", expired, "/login?flash=verify-link-expired"},
			{"unknown token", "does-not-exist", "/login?flash=verify-link-invalid"},
			{"empty token", "", "/login?flash=verify-link-invalid"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/verify-email/"+tc.token, nil)
				req = withChiToken(req, tc.token)
				rec := httptest.NewRecorder()
				f.handler.GetVerifyEmail(rec, req)

				res := rec.Result()
				if res.StatusCode != http.StatusFound {
					t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusFound)
				}
				if loc := res.Header.Get("Location"); loc != tc.wantLoc {
					t.Errorf("Location = %q, want %q", loc, tc.wantLoc)
				}
			})
		}
	})
}

// ─── POST /verify-email/resend ───────────────────────────────────────────────

// newResendRouter wires the resend handler with the same middleware ordering
// run.go uses: session required, then session-bound CSRF.
func newResendRouter(f *handlerFixture) http.Handler {
	r := chi.NewRouter()
	r.With(
		session.RequireSession(f.sessionSvc, f.cfg),
		csrf.ProtectAuthenticated(f.cfg.Session.EffectiveCookieName()),
	).Post("/verify-email/resend", f.handler.PostVerifyEmailResend)
	return r
}

func TestHandler_PostVerifyEmailResend_RequiresSessionAndCSRF(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	sender := &recordingSender{}
	f := newFullHandlerFixtureWith(t, true, withSMTP, sender)
	u, err := f.userSvc.Register(ctx, "resenduser", "resend@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.EmailVerified {
		t.Fatal("fixture user is verified; resend is only reachable for unverified accounts")
	}

	sessionToken, _, err := f.sessionSvc.CreateSession(ctx, u.ID, nil, "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	server := httptest.NewServer(newResendRouter(f))
	defer server.Close()

	// Do not follow redirects: the router only mounts the resend handler, so a
	// followed redirect would 404 and hide the status we want to assert.
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	post := func(t *testing.T, cookieValue, csrfToken string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+"/verify-email/resend", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if cookieValue != "" {
			req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: cookieValue})
		}
		if csrfToken != "" {
			req.Header.Set(csrf.HeaderName, csrfToken)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("without a session it redirects to login", func(t *testing.T) {
		resp := post(t, "", "")
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
		}
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
			t.Errorf("Location = %q, want a /login redirect", loc)
		}
		if got := len(sender.sent()); got != 0 {
			t.Errorf("emails sent without a session = %d, want 0", got)
		}
	})

	t.Run("with a session but no CSRF token it is forbidden", func(t *testing.T) {
		resp := post(t, sessionToken, "")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
		if got := len(sender.sent()); got != 0 {
			t.Errorf("emails sent without CSRF = %d, want 0", got)
		}
	})

	t.Run("with a session and a valid CSRF token it sends a fresh link", func(t *testing.T) {
		// An older unused token must be invalidated by the resend.
		stale, err := f.userSvc.CreateEmailVerificationToken(ctx, u.ID, u.Email)
		if err != nil {
			t.Fatalf("create stale token: %v", err)
		}

		csrfToken, err := csrf.GenerateToken(sessionToken)
		if err != nil {
			t.Fatalf("generate csrf token: %v", err)
		}

		resp := post(t, sessionToken, csrfToken)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
		}
		if loc := resp.Header.Get("Location"); loc != "/?flash=verify-resent" {
			t.Errorf("Location = %q, want %q", loc, "/?flash=verify-resent")
		}

		emails := sender.sent()
		if len(emails) != 1 {
			t.Fatalf("emails sent = %d, want 1", len(emails))
		}

		if _, err := f.userSvc.ConsumeEmailVerificationToken(ctx, stale.Token); !errors.Is(err, user.ErrEmailVerificationTokenNotFound) {
			t.Errorf("stale token after resend: got %v, want ErrEmailVerificationTokenNotFound", err)
		}

		freshToken := strings.TrimPrefix(emails[0].URL, "https://auth.example.com/verify-email/")
		if freshToken == "" || freshToken == emails[0].URL {
			t.Fatalf("could not extract token from URL %q", emails[0].URL)
		}
		if _, err := f.userSvc.ConsumeEmailVerificationToken(ctx, freshToken); err != nil {
			t.Errorf("new token from resend: %v", err)
		}
	})
}

func TestHandler_PostVerifyEmailResend_AlreadyVerified(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	sender := &recordingSender{}
	f := newFullHandlerFixtureWith(t, true, withSMTP, sender)
	u, err := f.userSvc.Register(ctx, "resend_verified", "resend_verified@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := f.userSvc.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	// Re-read so the context user matches what session validation would see.
	u, err = user.NewStore(f.db).GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/verify-email/resend", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	f.handler.PostVerifyEmailResend(rec, req)

	if loc := rec.Result().Header.Get("Location"); loc != "/?flash=email-already-verified" {
		t.Errorf("Location = %q, want %q", loc, "/?flash=email-already-verified")
	}
	if got := len(sender.sent()); got != 0 {
		t.Errorf("emails sent for an already-verified user = %d, want 0", got)
	}
}

// ─── Dashboard banner ────────────────────────────────────────────────────────

func TestHandler_GetDashboard_EmailVerificationBanner(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name       string
		verified   bool
		wantBanner bool
	}{
		{name: "unverified shows the banner and resend form", verified: false, wantBanner: true},
		{name: "verified shows no banner", verified: true, wantBanner: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFullHandlerFixtureWith(t, true, withSMTP, noopSender{})
			u, err := f.userSvc.Register(ctx, "banner", "banner@example.com", "password123")
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			if tc.verified {
				if err := f.userSvc.MarkEmailVerified(ctx, u.ID); err != nil {
					t.Fatalf("MarkEmailVerified: %v", err)
				}
			}
			// Re-read so the handler sees the same state as the database.
			u, err = user.NewStore(f.db).GetByID(ctx, u.ID)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if u.EmailVerified != tc.verified {
				t.Fatalf("fixture EmailVerified = %v, want %v", u.EmailVerified, tc.verified)
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = req.WithContext(session.WithUser(req.Context(), u))
			rec := httptest.NewRecorder()
			f.handler.GetDashboard(rec, req)

			res := rec.Result()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("GetDashboard: status = %d, want %d", res.StatusCode, http.StatusOK)
			}
			body := rec.Body.String()

			hasBanner := strings.Contains(body, "Verify your email")
			if hasBanner != tc.wantBanner {
				t.Errorf("banner present = %v, want %v", hasBanner, tc.wantBanner)
			}
			hasForm := strings.Contains(body, `action="/verify-email/resend"`)
			if hasForm != tc.wantBanner {
				t.Errorf("resend form present = %v, want %v", hasForm, tc.wantBanner)
			}
			// The empty-state branch must still render the banner (new users
			// usually have no app access yet).
			if tc.wantBanner && !strings.Contains(body, "Contact your administrator to get access.") {
				t.Error("expected the empty state alongside the banner for a user with no apps")
			}
		})
	}
}

// ─── Magic-link sign-in proves mailbox control ───────────────────────────────

func TestHandler_GetMagicLinkVerify_VerifiesEmail(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	sender := &recordingSender{}
	f := newFullHandlerFixtureWith(t, true, withSMTP, sender)

	u, err := f.userSvc.Register(ctx, "magicverify", "magicverify@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.EmailVerified {
		t.Fatal("fixture user is verified; the magic-link flip cannot be observed")
	}

	tok, err := f.userSvc.CreateMagicLinkToken(ctx, u.ID, 15)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token="+tok.Token, nil)
	rec := httptest.NewRecorder()
	f.handler.GetMagicLinkVerify(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusFound)
	}
	var sessionCookieSet bool
	for _, c := range res.Cookies() {
		if c.Name == f.cfg.Session.CookieName && c.Value != "" {
			sessionCookieSet = true
			break
		}
	}
	if !sessionCookieSet {
		t.Fatal("magic-link sign-in did not set a session cookie")
	}

	fresh, err := user.NewStore(f.db).GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !fresh.EmailVerified {
		t.Error("EmailVerified = false after signing in with a magic link; want true")
	}
}
