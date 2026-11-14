package user_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/user"
)

// ─── fake passkey bridge ─────────────────────────────────────────────────────

// fakeSecondFactorPasskey stands in for *webauthn.Handler at the user package's
// consumer boundary. It models the real contract: begin records a ceremony for
// one challenge token, finish succeeds only for the token it was begun for and
// only once, and neither creates a session.
type fakeSecondFactorPasskey struct {
	mu       sync.Mutex
	hasCred  map[string]bool
	begun    map[string]string // bind key -> user ID
	beginErr error
}

func newFakeSecondFactorPasskey() *fakeSecondFactorPasskey {
	return &fakeSecondFactorPasskey{
		hasCred: map[string]bool{},
		begun:   map[string]string{},
	}
}

func (p *fakeSecondFactorPasskey) HasCredentials(_ context.Context, userID string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hasCred[userID], nil
}

func (p *fakeSecondFactorPasskey) BeginSecondFactor(_ context.Context, u *user.User, bindKey string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.beginErr != nil {
		return nil, p.beginErr
	}
	if !p.hasCred[u.ID] {
		return nil, errors.New("fake: no credentials")
	}
	p.begun[bindKey] = u.ID
	return []byte(`{"publicKey":{"challenge":"ZmFrZS1jaGFsbGVuZ2U"}}`), nil
}

func (p *fakeSecondFactorPasskey) FinishSecondFactor(_ context.Context, _ *http.Request, u *user.User, bindKey string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	bound, ok := p.begun[bindKey]
	if !ok || bound != u.ID {
		return errors.New("fake: no ceremony bound to this challenge")
	}
	delete(p.begun, bindKey)
	return nil
}

// newPasskeyFixture builds the usual handler fixture with a fake passkey bridge
// wired in.
func newPasskeyFixture(t *testing.T) (*handlerFixture, *fakeSecondFactorPasskey) {
	t.Helper()
	f := newFullHandlerFixture(t, true)
	p := newFakeSecondFactorPasskey()
	f.handler.SetSecondFactorPasskey(p)
	return f, p
}

// ─── request helpers ─────────────────────────────────────────────────────────

func postPasskeyBegin(t *testing.T, f *handlerFixture, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login/mfa/passkey/begin", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.AddCookie(&http.Cookie{Name: mfaCookie(f), Value: token})
	}
	rec := httptest.NewRecorder()
	f.handler.PostMFAPasskeyBegin(rec, req)
	return rec
}

func postPasskeyFinish(t *testing.T, f *handlerFixture, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login/mfa/passkey/finish", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.AddCookie(&http.Cookie{Name: mfaCookie(f), Value: token})
	}
	rec := httptest.NewRecorder()
	f.handler.PostMFAPasskeyFinish(rec, req)
	return rec
}

// beginChallengeFor starts a password sign-in for username with rd and returns
// the pending-challenge token, asserting no session was created by it.
func beginChallengeFor(t *testing.T, f *handlerFixture, username, rd string) (*user.User, string) {
	t.Helper()
	u, err := f.userStore.GetByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	before := countSessions(t, f, u.ID)

	rec := postLoginWithTarget(t, f, username, "password123", rd)
	if loc := rec.Result().Header.Get("Location"); loc != "/login/mfa" {
		t.Fatalf("password step Location = %q, want /login/mfa", loc)
	}
	if got := sessionCookieValue(f, rec); got != "" {
		t.Fatal("a session cookie was set before the second factor")
	}
	if n := countSessions(t, f, u.ID); n != before {
		t.Fatalf("sessions after the password step = %d, want %d", n, before)
	}
	return u, challengeTokenFrom(t, f, rec)
}

// postLoginWithTarget posts the password form with a return target.
func postLoginWithTarget(t *testing.T, f *handlerFixture, username, password, rd string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	if rd != "" {
		form.Set("rd", rd)
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostLogin(rec, req)
	return rec
}

// ─── tests ───────────────────────────────────────────────────────────────────

// TestMFAPasskey_CompletesPendingChallenge is the core flow: a password step
// yields only a challenge, begin issues options, and only finish produces a
// session — through the same completion path as a code.
func TestMFAPasskey_CompletesPendingChallenge(t *testing.T) {
	t.Parallel()
	f, p := newPasskeyFixture(t)
	u := registerUser(t, f, "passkey-user")
	enrollMFA(t, f, u)
	p.hasCred[u.ID] = true

	_, token := beginChallengeFor(t, f, "passkey-user", "/sessions")

	// Begin hands out options but must not sign anyone in.
	rec := postPasskeyBegin(t, f, token)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("begin status = %d, want 200; body: %s", rec.Result().StatusCode, rec.Body.String())
	}
	if ct := rec.Result().Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("begin Content-Type = %q, want application/json", ct)
	}
	var options map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &options); err != nil {
		t.Fatalf("begin body is not JSON: %v", err)
	}
	if _, ok := options["publicKey"]; !ok {
		t.Errorf("begin body has no publicKey: %s", rec.Body.String())
	}
	if got := sessionCookieValue(f, rec); got != "" {
		t.Errorf("begin set a session cookie: %q", got)
	}
	if n := countSessions(t, f, u.ID); n != 0 {
		t.Fatalf("sessions after begin = %d, want 0", n)
	}
	if _, err := f.mfaSvc.Challenge(context.Background(), token); err != nil {
		t.Fatalf("challenge was consumed by begin: %v", err)
	}

	// Finish: a session for the original return target, pending state cleared.
	out := postPasskeyFinish(t, f, token)
	res := out.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("finish status = %d, want 200; body: %s", res.StatusCode, out.Body.String())
	}
	var result struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
		t.Fatalf("finish body is not JSON: %v", err)
	}
	if result.Redirect != "/sessions" {
		t.Errorf("redirect = %q, want /sessions", result.Redirect)
	}
	if got := sessionCookieValue(f, out); got == "" {
		t.Fatal("no session cookie after a verified passkey")
	}
	if c := cookieByName(out, mfaCookie(f)); c == nil || c.Value != "" {
		t.Error("pending challenge cookie was not cleared")
	}
	if _, err := f.mfaSvc.Challenge(context.Background(), token); err == nil {
		t.Error("challenge row survived a completed sign-in")
	}
	if n := countSessions(t, f, u.ID); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}

	e := findEvent(listAuthEvents(t, f), authlog.EventMFASuccess)
	if e == nil {
		t.Fatal("no mfa.success event")
	}
	if e.Detail != "passkey" {
		t.Errorf("mfa.success detail = %q, want passkey", e.Detail)
	}
}

// TestMFAPasskey_BindKeyIsolation proves a ceremony begun for one pending
// challenge cannot complete another, and that the other challenge survives.
func TestMFAPasskey_BindKeyIsolation(t *testing.T) {
	t.Parallel()
	f, p := newPasskeyFixture(t)

	alice := registerUser(t, f, "alice-pk")
	enrollMFA(t, f, alice)
	p.hasCred[alice.ID] = true

	bob := registerUser(t, f, "bob-pk")
	enrollMFA(t, f, bob)
	p.hasCred[bob.ID] = true

	_, tokenAlice := beginChallengeFor(t, f, "alice-pk", "/")
	_, tokenBob := beginChallengeFor(t, f, "bob-pk", "/")

	if rec := postPasskeyBegin(t, f, tokenAlice); rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("begin for alice: %d", rec.Result().StatusCode)
	}

	// The assertion was begun for Alice's challenge; presenting Bob's cookie
	// must not complete Bob's sign-in.
	rec := postPasskeyFinish(t, f, tokenBob)
	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("finish with another challenge's cookie: status %d, want 401", rec.Result().StatusCode)
	}
	if got := sessionCookieValue(f, rec); got != "" {
		t.Errorf("session cookie set by a mismatched finish: %q", got)
	}
	if n := countSessions(t, f, bob.ID); n != 0 {
		t.Errorf("bob's sessions = %d, want 0", n)
	}
	if _, err := f.mfaSvc.Challenge(context.Background(), tokenBob); err != nil {
		t.Fatalf("bob's challenge was consumed by a failed assertion: %v", err)
	}

	// Alice's own ceremony is untouched and still completes.
	if rec := postPasskeyFinish(t, f, tokenAlice); rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("finish for alice after isolation failure: %d; body: %s", rec.Result().StatusCode, rec.Body.String())
	}
	if n := countSessions(t, f, alice.ID); n != 1 {
		t.Errorf("alice's sessions = %d, want 1", n)
	}
}

// TestMFAPasskey_ExpiredChallenge proves both endpoints refuse a challenge past
// its five-minute life and never create a session.
func TestMFAPasskey_ExpiredChallenge(t *testing.T) {
	t.Parallel()
	f, p := newPasskeyFixture(t)
	u := registerUser(t, f, "expired-pk")
	enrollMFA(t, f, u)
	p.hasCred[u.ID] = true

	_, token := beginChallengeFor(t, f, "expired-pk", "/")
	f.clock.Advance(mfa.ChallengeTTL + time.Second)

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"begin":  postPasskeyBegin(t, f, token),
		"finish": postPasskeyFinish(t, f, token),
	} {
		if got := rec.Result().StatusCode; got != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", name, got)
		}
		if got := sessionCookieValue(f, rec); got != "" {
			t.Errorf("%s set a session cookie: %q", name, got)
		}
	}
	if n := countSessions(t, f, u.ID); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
}

// TestMFAPasskey_Unavailable proves the option is refused server-side when the
// user has no passkey or the bridge is not wired.
func TestMFAPasskey_Unavailable(t *testing.T) {
	t.Parallel()

	t.Run("user without credentials", func(t *testing.T) {
		t.Parallel()
		f, _ := newPasskeyFixture(t)
		u := registerUser(t, f, "credless-pk")
		enrollMFA(t, f, u)

		_, token := beginChallengeFor(t, f, "credless-pk", "/")
		if got := postPasskeyBegin(t, f, token).Result().StatusCode; got != http.StatusNotFound {
			t.Errorf("begin status = %d, want 404", got)
		}
	})

	t.Run("no bridge wired", func(t *testing.T) {
		t.Parallel()
		f, _ := newPasskeyFixture(t)
		u := registerUser(t, f, "nowire-pk")
		enrollMFA(t, f, u)
		f.handler.SetSecondFactorPasskey(nil)

		_, token := beginChallengeFor(t, f, "nowire-pk", "/")
		if got := postPasskeyBegin(t, f, token).Result().StatusCode; got != http.StatusNotFound {
			t.Errorf("begin status = %d, want 404", got)
		}
	})

	t.Run("ceremony fails to start", func(t *testing.T) {
		t.Parallel()
		f, p := newPasskeyFixture(t)
		u := registerUser(t, f, "beginfail-pk")
		enrollMFA(t, f, u)
		p.hasCred[u.ID] = true
		p.beginErr = errors.New("fake: ceremony unavailable")

		_, token := beginChallengeFor(t, f, "beginfail-pk", "/")
		if got := postPasskeyBegin(t, f, token).Result().StatusCode; got != http.StatusInternalServerError {
			t.Errorf("begin status = %d, want 500", got)
		}
		if findEvent(listAuthEvents(t, f), authlog.EventMFAFailure) == nil {
			t.Error("no mfa.failure event for a ceremony that failed to start")
		}
		if _, err := f.mfaSvc.Challenge(context.Background(), token); err != nil {
			t.Errorf("challenge was consumed by a failed begin: %v", err)
		}
	})
}

// TestMFAPasskey_DisabledGlobally proves the policy flag removes the option
// from both the page and the API.
func TestMFAPasskey_DisabledGlobally(t *testing.T) {
	t.Parallel()
	f, p := newPasskeyFixture(t)
	f.settings.values[user.SettingPasskeyEnabled] = "false"
	u := registerUser(t, f, "disabled-pk")
	enrollMFA(t, f, u)
	p.hasCred[u.ID] = true

	_, token := beginChallengeFor(t, f, "disabled-pk", "/")

	// The rendered page must not offer it.
	req := httptest.NewRequest(http.MethodGet, "/login/mfa", nil)
	req.AddCookie(&http.Cookie{Name: mfaCookie(f), Value: token})
	rec := httptest.NewRecorder()
	f.handler.GetMFALogin(rec, req)
	if strings.Contains(rec.Body.String(), "Use a passkey instead") {
		t.Error("the page offered a passkey while passkeys are disabled")
	}

	if got := postPasskeyBegin(t, f, token).Result().StatusCode; got != http.StatusNotFound {
		t.Errorf("begin status = %d, want 404", got)
	}
	if got := postPasskeyFinish(t, f, token).Result().StatusCode; got != http.StatusNotFound {
		t.Errorf("finish status = %d, want 404", got)
	}
}

// TestGetMFALogin_OffersPasskey checks the server-side decision behind the
// button: it renders only when a passkey can actually complete the challenge.
func TestGetMFALogin_OffersPasskey(t *testing.T) {
	t.Parallel()
	f, p := newPasskeyFixture(t)
	u := registerUser(t, f, "offer-pk")
	enrollMFA(t, f, u)

	_, token := beginChallengeFor(t, f, "offer-pk", "/")

	// No credential yet: the code field is the only second factor.
	req := httptest.NewRequest(http.MethodGet, "/login/mfa", nil)
	req.AddCookie(&http.Cookie{Name: mfaCookie(f), Value: token})
	rec := httptest.NewRecorder()
	f.handler.GetMFALogin(rec, req)
	if strings.Contains(rec.Body.String(), "Use a passkey instead") {
		t.Error("the page offered a passkey to a user without one")
	}

	p.hasCred[u.ID] = true
	req = httptest.NewRequest(http.MethodGet, "/login/mfa", nil)
	req.AddCookie(&http.Cookie{Name: mfaCookie(f), Value: token})
	rec = httptest.NewRecorder()
	f.handler.GetMFALogin(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "Use a passkey instead") {
		t.Error("the page did not offer a passkey to a user who has one")
	}
	if !strings.Contains(body, `id="passkey-mfa-btn"`) {
		t.Error("the passkey button is missing its passkey.js hook")
	}
	if !strings.Contains(body, `src="/static/passkey.js"`) {
		t.Error("the page does not load passkey.js")
	}
}

// TestMFAPasskey_CodeFallbackStillWorks proves a failed assertion leaves the
// challenge usable: a recovery code and then a fresh sign-in with a TOTP code
// still complete.
func TestMFAPasskey_CodeFallbackStillWorks(t *testing.T) {
	t.Parallel()
	f, p := newPasskeyFixture(t)
	u := registerUser(t, f, "fallback-pk")
	codes := enrollMFA(t, f, u)
	p.hasCred[u.ID] = true

	// Pre-existing quirk in internal/mfa: LooksLikeTOTP classifies any code
	// whose digits-only projection is six digits as a TOTP code, which is true
	// for ~4.5% of recovery codes. Pick one the TOTP path will not swallow so
	// this test is deterministic. (Reported; that package is out of scope here.)
	recoveryCode := codes[0]
	for _, c := range codes {
		if !mfa.LooksLikeTOTP(c) {
			recoveryCode = c
			break
		}
	}

	_, token := beginChallengeFor(t, f, "fallback-pk", "/")

	// A failed assertion (no ceremony bound to the token) records a failure and
	// keeps the challenge.
	rec := postPasskeyFinish(t, f, token)
	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("finish without a ceremony: status %d, want 401", rec.Result().StatusCode)
	}
	if findEvent(listAuthEvents(t, f), authlog.EventMFAFailure) == nil {
		t.Error("no mfa.failure event for the failed assertion")
	}
	if n := countSessions(t, f, u.ID); n != 0 {
		t.Fatalf("sessions after a failed assertion = %d, want 0", n)
	}

	// Recovery code on the same challenge.
	out := postMFALogin(t, f, token, recoveryCode)
	if loc := out.Result().Header.Get("Location"); loc != "/" {
		t.Errorf("recovery-code Location = %q, want /", loc)
	}
	if got := sessionCookieValue(f, out); got == "" {
		t.Fatal("no session cookie after a recovery code")
	}

	// TOTP still works for a new sign-in.
	f.clock.Advance(mfa.Period)
	var secret string
	if err := f.db.QueryRow(`SELECT secret FROM user_mfa WHERE user_id = ?`, u.ID).Scan(&secret); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	_, token2 := beginChallengeFor(t, f, "fallback-pk", "/")
	out = postMFALogin(t, f, token2, totpAt(t, secret, f.clock.Now()))
	if got := sessionCookieValue(f, out); got == "" {
		t.Fatal("no session cookie after a TOTP code")
	}
}
