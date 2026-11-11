package user_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// totpAt derives a 6-digit TOTP code independently of internal/mfa, so the two
// implementations cross-check each other instead of agreeing by construction.
func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.UTC().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// registerUser creates an active user and returns it.
func registerUser(t *testing.T, f *handlerFixture, username string) *user.User {
	t.Helper()
	if _, err := f.userSvc.Register(context.Background(), username, username+"@example.com", "password123"); err != nil {
		t.Fatalf("register %q: %v", username, err)
	}
	u, err := f.userStore.GetByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("get user %q: %v", username, err)
	}
	return u
}

// enrollMFA completes a TOTP enrollment and returns the recovery codes.
func enrollMFA(t *testing.T, f *handlerFixture, u *user.User) []string {
	t.Helper()
	ctx := context.Background()
	enr, err := f.mfaSvc.BeginEnrollment(ctx, u.ID, u.Username)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	codes, err := f.mfaSvc.ConfirmEnrollment(ctx, u.ID, totpAt(t, enr.Secret, f.clock.Now()))
	if err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	return codes
}

// sessionFor creates a session and returns its token.
func sessionFor(t *testing.T, f *handlerFixture, userID string) string {
	t.Helper()
	token, _, err := f.sessionSvc.CreateSession(context.Background(), userID, nil, "192.0.2.10", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return token
}

// cookieByName returns the named cookie from a recorder, or nil.
func cookieByName(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// mfaCookie returns the pending-challenge cookie name for the fixture config.
func mfaCookie(f *handlerFixture) string {
	if f.cfg.Session.CookieSecure {
		return "__Host-" + user.MFACookieName
	}
	return user.MFACookieName
}

// postMFALogin submits the second-factor form with the given challenge cookie.
func postMFALogin(t *testing.T, f *handlerFixture, token, code string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("code", code)
	req := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		req.AddCookie(&http.Cookie{Name: mfaCookie(f), Value: token})
	}
	rec := httptest.NewRecorder()
	f.handler.PostMFALogin(rec, req)
	return rec
}

// challengeTokenFrom extracts the pending-challenge token from a login response.
func challengeTokenFrom(t *testing.T, f *handlerFixture, rec *httptest.ResponseRecorder) string {
	t.Helper()
	c := cookieByName(rec, mfaCookie(f))
	if c == nil || c.Value == "" {
		t.Fatalf("no %q cookie in response", mfaCookie(f))
	}
	return c.Value
}

// sessionCookieValue returns the session cookie value from a response, or "".
func sessionCookieValue(f *handlerFixture, rec *httptest.ResponseRecorder) string {
	c := cookieByName(rec, f.cfg.Session.CookieName)
	if c == nil {
		return ""
	}
	return c.Value
}

// countSessions returns how many sessions exist for a user.
func countSessions(t *testing.T, f *handlerFixture, userID string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(
		`SELECT COUNT(*) FROM sessions WHERE user_id = ?`, userID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// findEvent reports whether an event with the given name exists.
func findEvent(events []*authlog.Event, name string) *authlog.Event {
	for _, e := range events {
		if e.Event == name {
			return e
		}
	}
	return nil
}

// ─── login flow ──────────────────────────────────────────────────────────────

// TestMFALogin_ChallengeInsteadOfSession is the core security property: a
// correct password for an MFA account yields a challenge and no session.
func TestMFALogin_ChallengeInsteadOfSession(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "malice")
	enrollMFA(t, f, u)

	rec := postLogin(t, f, "malice", "password123")
	res := rec.Result()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d; want %d", res.StatusCode, http.StatusFound)
	}
	if loc := res.Header.Get("Location"); loc != "/login/mfa" {
		t.Errorf("Location = %q; want /login/mfa", loc)
	}
	if got := sessionCookieValue(f, rec); got != "" {
		t.Errorf("a session cookie was set before the second factor: %q", got)
	}
	if n := countSessions(t, f, u.ID); n != 0 {
		t.Errorf("sessions created before the second factor: %d", n)
	}
	if challengeTokenFrom(t, f, rec) == "" {
		t.Error("no challenge cookie issued")
	}

	e := findEvent(listAuthEvents(t, f), authlog.EventMFAChallenge)
	if e == nil {
		t.Fatal("no mfa.challenge event recorded")
	}
	if e.UserID != u.ID {
		t.Errorf("mfa.challenge user = %q; want %q", e.UserID, u.ID)
	}
	if findEvent(listAuthEvents(t, f), authlog.EventLoginSuccess) != nil {
		t.Error("login.success was recorded before the second factor")
	}
}

// TestMFALogin_ValidTOTPCompletesLogin proves the challenge completes into a
// session with the original return target.
func TestMFALogin_ValidTOTPCompletesLogin(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "nick")
	enrollMFA(t, f, u)

	// A different step from the one enrollment consumed.
	f.clock.Advance(mfa.Period)

	form := url.Values{}
	form.Set("username", "nick")
	form.Set("password", "password123")
	form.Set("rd", "/sessions")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostLogin(rec, req)
	token := challengeTokenFrom(t, f, rec)

	c, err := f.mfaSvc.Challenge(context.Background(), token)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if c.ReturnTo != "/sessions" {
		t.Fatalf("challenge return target = %q; want /sessions", c.ReturnTo)
	}

	cred, err := f.mfaSvc.Status(context.Background(), u.ID)
	if err != nil || !cred.Enabled {
		t.Fatalf("status = %+v, %v; want enabled", cred, err)
	}

	// Read the secret straight from the store to derive a valid code.
	var secret string
	if err := f.db.QueryRow(`SELECT secret FROM user_mfa WHERE user_id = ?`, u.ID).Scan(&secret); err != nil {
		t.Fatalf("read secret: %v", err)
	}

	out := postMFALogin(t, f, token, totpAt(t, secret, f.clock.Now()))
	res := out.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d; want %d", res.StatusCode, http.StatusFound)
	}
	if loc := res.Header.Get("Location"); loc != "/sessions" {
		t.Errorf("Location = %q; want /sessions", loc)
	}
	if sessionCookieValue(f, out) == "" {
		t.Fatal("no session cookie after a valid code")
	}
	if n := countSessions(t, f, u.ID); n != 1 {
		t.Errorf("sessions = %d; want 1", n)
	}
	if c := cookieByName(out, mfaCookie(f)); c == nil || c.Value != "" {
		t.Error("pending challenge cookie was not cleared")
	}
	if _, err := f.mfaSvc.Challenge(context.Background(), token); err == nil {
		t.Error("challenge row survived a successful verification")
	}

	e := findEvent(listAuthEvents(t, f), authlog.EventMFASuccess)
	if e == nil {
		t.Fatal("no mfa.success event")
	}
	if e.Detail != "totp" {
		t.Errorf("mfa.success detail = %q; want totp", e.Detail)
	}
}

// TestMFALogin_ReplayedTOTPRejected proves a code cannot be used twice, even
// against a freshly issued challenge.
func TestMFALogin_ReplayedTOTPRejected(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "olive")
	enrollMFA(t, f, u)
	f.clock.Advance(mfa.Period)

	var secret string
	if err := f.db.QueryRow(`SELECT secret FROM user_mfa WHERE user_id = ?`, u.ID).Scan(&secret); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	code := totpAt(t, secret, f.clock.Now())

	first := postLogin(t, f, "olive", "password123")
	if rec := postMFALogin(t, f, challengeTokenFrom(t, f, first), code); sessionCookieValue(f, rec) == "" {
		t.Fatal("the first use of a valid code did not create a session")
	}

	second := postLogin(t, f, "olive", "password123")
	rec := postMFALogin(t, f, challengeTokenFrom(t, f, second), code)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("replay status = %d; want 200 (re-rendered form)", rec.Result().StatusCode)
	}
	if sessionCookieValue(f, rec) != "" {
		t.Fatal("a replayed TOTP code created a second session")
	}
	if n := countSessions(t, f, u.ID); n != 1 {
		t.Errorf("sessions = %d; want 1", n)
	}
	if e := findEvent(listAuthEvents(t, f), authlog.EventMFAFailure); e == nil {
		t.Error("no mfa.failure event for the replay")
	}
}

// TestMFALogin_RecoveryCodeSingleUse drives the recovery-code path end to end.
func TestMFALogin_RecoveryCodeSingleUse(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "peggy")
	codes := enrollMFA(t, f, u)

	first := postLogin(t, f, "peggy", "password123")
	out := postMFALogin(t, f, challengeTokenFrom(t, f, first), codes[0])
	if sessionCookieValue(f, out) == "" {
		t.Fatal("a recovery code did not create a session")
	}
	if e := findEvent(listAuthEvents(t, f), authlog.EventMFASuccess); e == nil || e.Detail != "recovery" {
		t.Fatalf("mfa.success detail = %v; want recovery", e)
	}

	// The code is spent; a new challenge must refuse it.
	second := postLogin(t, f, "peggy", "password123")
	rec := postMFALogin(t, f, challengeTokenFrom(t, f, second), codes[0])
	if sessionCookieValue(f, rec) != "" {
		t.Fatal("the same recovery code worked twice")
	}

	// A different code still works, including with user-typed formatting.
	third := postLogin(t, f, "peggy", "password123")
	typed := strings.ToLower(codes[1]) + " "
	if out := postMFALogin(t, f, challengeTokenFrom(t, f, third), typed); sessionCookieValue(f, out) == "" {
		t.Fatal("an unused recovery code in lower case was rejected")
	}
}

// TestMFALogin_ExpiredChallengeRejected proves the five-minute window is real.
func TestMFALogin_ExpiredChallengeRejected(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "quinn")
	enrollMFA(t, f, u)
	f.clock.Advance(mfa.Period)

	rec := postLogin(t, f, "quinn", "password123")
	token := challengeTokenFrom(t, f, rec)

	f.clock.Advance(mfa.ChallengeTTL + time.Second)

	var secret string
	if err := f.db.QueryRow(`SELECT secret FROM user_mfa WHERE user_id = ?`, u.ID).Scan(&secret); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	out := postMFALogin(t, f, token, totpAt(t, secret, f.clock.Now()))
	if loc := out.Result().Header.Get("Location"); loc != "/login?flash=mfa-expired" {
		t.Fatalf("Location = %q; want /login?flash=mfa-expired", loc)
	}
	if sessionCookieValue(f, out) != "" {
		t.Fatal("an expired challenge produced a session")
	}
}

// TestMFALogin_WrongCodeStaysOnForm proves a bad code re-renders without
// burning the challenge.
func TestMFALogin_WrongCodeStaysOnForm(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "rupert")
	enrollMFA(t, f, u)
	f.clock.Advance(mfa.Period)

	rec := postLogin(t, f, "rupert", "password123")
	token := challengeTokenFrom(t, f, rec)

	out := postMFALogin(t, f, token, "000000")
	if out.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", out.Result().StatusCode)
	}
	if !strings.Contains(out.Body.String(), "not valid") {
		t.Error("no error message rendered")
	}
	if sessionCookieValue(f, out) != "" {
		t.Fatal("a wrong code created a session")
	}
	if _, err := f.mfaSvc.Challenge(context.Background(), token); err != nil {
		t.Fatalf("challenge was burned by a wrong code: %v", err)
	}

	// The challenge still works with the right code.
	var secret string
	if err := f.db.QueryRow(`SELECT secret FROM user_mfa WHERE user_id = ?`, u.ID).Scan(&secret); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if rec := postMFALogin(t, f, token, totpAt(t, secret, f.clock.Now())); sessionCookieValue(f, rec) == "" {
		t.Fatal("the challenge no longer works after a failed attempt")
	}
}

// TestMFALogin_NoChallengeRedirects covers a bare visit and a stale cookie.
func TestMFALogin_NoChallengeRedirects(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	tests := []struct {
		name  string
		token string
	}{
		{"no cookie", ""},
		{"unknown token", "not-a-real-challenge"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/login/mfa", nil)
			if tt.token != "" {
				req.AddCookie(&http.Cookie{Name: mfaCookie(f), Value: tt.token})
			}
			rec := httptest.NewRecorder()
			f.handler.GetMFALogin(rec, req)
			if loc := rec.Result().Header.Get("Location"); loc != "/login?flash=mfa-expired" {
				t.Errorf("Location = %q; want /login?flash=mfa-expired", loc)
			}
			if c := cookieByName(rec, mfaCookie(f)); c == nil || c.Value != "" {
				t.Error("stale pending cookie was not cleared")
			}
		})
	}
}

// TestMFALogin_PendingEnrollmentDoesNotChallenge: an abandoned enrollment must
// not lock the password login out of the account.
func TestMFALogin_PendingEnrollmentDoesNotChallenge(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "sam")

	if _, err := f.mfaSvc.BeginEnrollment(context.Background(), u.ID, u.Username); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}

	rec := postLogin(t, f, "sam", "password123")
	if loc := rec.Result().Header.Get("Location"); loc == "/login/mfa" {
		t.Fatal("a pending (unverified) enrollment forced a second factor")
	}
	if sessionCookieValue(f, rec) == "" {
		t.Fatal("no session for a user with only a pending enrollment")
	}
}

// ─── enrollment ──────────────────────────────────────────────────────────────

// TestMFASetup_EnrollFlow drives GET and POST /mfa/setup through the handler.
func TestMFASetup_EnrollFlow(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "tara")
	token := sessionFor(t, f, u.ID)
	ctx := session.WithUser(context.Background(), u)

	// GET shows the secret, the URI and a copy hook.
	req := httptest.NewRequest(http.MethodGet, "/mfa/setup?required=1", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	f.handler.GetMFASetup(rec, req)
	body := rec.Body.String()
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Result().StatusCode)
	}
	for _, want := range []string{"Setup key", "otpauth://totp/", "data-copy=\"#mfa-secret\"", "An administrator requires"} {
		if !strings.Contains(body, want) {
			t.Errorf("setup page missing %q", want)
		}
	}

	var secret string
	if err := f.db.QueryRow(`SELECT secret FROM user_mfa WHERE user_id = ?`, u.ID).Scan(&secret); err != nil {
		t.Fatalf("read pending secret: %v", err)
	}

	// A wrong code re-renders the same secret with an error.
	form := url.Values{}
	form.Set("code", "000000")
	form.Set("required", "1")
	req = httptest.NewRequest(http.MethodPost, "/mfa/setup", strings.NewReader(form.Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	f.handler.PostMFASetup(rec, req)
	body = rec.Body.String()
	if rec.Result().StatusCode != http.StatusOK || !strings.Contains(body, "not valid") {
		t.Fatalf("wrong code: status %d, body lacks error", rec.Result().StatusCode)
	}
	if !strings.Contains(body, mfa.FormatSecret(secret)) {
		t.Error("the pending secret rotated after a failed attempt")
	}
	if e := findEvent(listAuthEvents(t, f), authlog.EventMFAFailure); e == nil {
		t.Error("no mfa.failure event for a failed enrollment")
	}

	// The right code enables and shows ten recovery codes exactly once.
	form.Set("code", totpAt(t, secret, f.clock.Now()))
	req = httptest.NewRequest(http.MethodPost, "/mfa/setup", strings.NewReader(form.Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	f.handler.PostMFASetup(rec, req)
	body = rec.Body.String()
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Result().StatusCode)
	}
	if !strings.Contains(body, "Save your recovery codes") {
		t.Error("recovery-code page not rendered")
	}
	if n := strings.Count(body, "<li>"); n != mfa.RecoveryCodeCount {
		t.Errorf("rendered %d recovery codes; want %d", n, mfa.RecoveryCodeCount)
	}
	if st, err := f.mfaSvc.Status(ctx, u.ID); err != nil || !st.Enabled {
		t.Fatalf("status after enrollment = %+v, %v; want enabled", st, err)
	}
	if e := findEvent(listAuthEvents(t, f), authlog.EventMFAEnrolled); e == nil {
		t.Error("no mfa.enrolled event")
	}

	// GET again redirects: already enabled.
	req = httptest.NewRequest(http.MethodGet, "/mfa/setup", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	f.handler.GetMFASetup(rec, req)
	if loc := rec.Result().Header.Get("Location"); loc != "/passkeys?flash=mfa-on" {
		t.Errorf("Location = %q; want /passkeys?flash=mfa-on", loc)
	}

	// A second POST cannot rotate the working credential.
	req = httptest.NewRequest(http.MethodPost, "/mfa/setup", strings.NewReader(form.Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	f.handler.PostMFASetup(rec, req)
	if loc := rec.Result().Header.Get("Location"); loc != "/passkeys?flash=mfa-on" {
		t.Errorf("re-POST Location = %q; want /passkeys?flash=mfa-on", loc)
	}

	// The session that enrolled is untouched (the flow never revokes sessions).
	if _, _, err := f.sessionSvc.ValidateSession(context.Background(), token); err != nil {
		t.Fatalf("enrolling session became invalid: %v", err)
	}
}

// TestMFADisable_RequiresPassword proves the password gate on the Security page
// actions and that a successful disable removes both tables.
func TestMFADisable_RequiresPassword(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "ursula")
	enrollMFA(t, f, u)
	ctx := session.WithUser(context.Background(), u)

	post := func(password string) *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set("password", password)
		req := httptest.NewRequest(http.MethodPost, "/mfa/disable", strings.NewReader(form.Encode())).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.handler.PostMFADisable(rec, req)
		return rec
	}

	rec := post("wrong-password")
	if loc := rec.Result().Header.Get("Location"); loc != "/passkeys?flash=mfa-password-invalid" {
		t.Fatalf("wrong password Location = %q", loc)
	}
	if st, _ := f.mfaSvc.Status(ctx, u.ID); !st.Enabled {
		t.Fatal("a wrong password disabled MFA")
	}

	rec = post("password123")
	if loc := rec.Result().Header.Get("Location"); loc != "/passkeys?flash=mfa-disabled" {
		t.Fatalf("right password Location = %q", loc)
	}
	if st, _ := f.mfaSvc.Status(ctx, u.ID); st.Enabled {
		t.Fatal("MFA still enabled after disable")
	}
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = ?`, u.ID).Scan(&n); err != nil {
		t.Fatalf("count codes: %v", err)
	}
	if n != 0 {
		t.Errorf("recovery codes survived disable: %d", n)
	}
	if e := findEvent(listAuthEvents(t, f), authlog.EventMFADisabled); e == nil {
		t.Error("no mfa.disabled event")
	}
}

// TestMFARecoveryCodes_Regenerate proves the password gate and that old codes
// stop working.
func TestMFARecoveryCodes_Regenerate(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	u := registerUser(t, f, "vera")
	oldCodes := enrollMFA(t, f, u)
	ctx := session.WithUser(context.Background(), u)

	form := url.Values{}
	form.Set("password", "wrong-password")
	req := httptest.NewRequest(http.MethodPost, "/mfa/recovery-codes", strings.NewReader(form.Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostMFARecoveryCodes(rec, req)
	if loc := rec.Result().Header.Get("Location"); loc != "/passkeys?flash=mfa-password-invalid" {
		t.Fatalf("wrong password Location = %q", loc)
	}

	form.Set("password", "password123")
	req = httptest.NewRequest(http.MethodPost, "/mfa/recovery-codes", strings.NewReader(form.Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	f.handler.PostMFARecoveryCodes(rec, req)
	body := rec.Body.String()
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Result().StatusCode)
	}
	if !strings.Contains(body, "New recovery codes") {
		t.Error("regenerated-code page not rendered")
	}
	if n := strings.Count(body, "<li>"); n != mfa.RecoveryCodeCount {
		t.Errorf("rendered %d codes; want %d", n, mfa.RecoveryCodeCount)
	}

	if _, err := f.mfaSvc.Verify(ctx, u.ID, oldCodes[0]); err == nil {
		t.Fatal("an old recovery code still works after regeneration")
	}
	if e := findEvent(listAuthEvents(t, f), authlog.EventMFACodesRegenerated); e == nil {
		t.Error("no mfa.codes_regenerated event")
	}
}

// ─── global policy gate ──────────────────────────────────────────────────────

// buildGatedRouter mirrors the route groups run.go wires: MFA routes and the
// Security page outside the gate, app routes inside it, logout outside
// everything.
func buildGatedRouter(f *handlerFixture) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(session.RequireSession(f.sessionSvc, f.cfg))
		f.handler.MFARoutes(r, nil)
		r.Group(func(r chi.Router) {
			r.Use(f.handler.RequireMFA)
			r.Get("/", f.handler.GetDashboard)
			r.Get("/sessions", f.handler.GetDashboard) // stands in for the sessions page
			r.Get("/admin", f.handler.GetDashboard)    // same middleware the admin group uses
		})
	})
	r.Get("/logout", f.handler.GetLogout)
	return r
}

func getWithSession(router http.Handler, f *handlerFixture, path, sessionToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: sessionToken})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestRequireMFA_Gate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfgOn    bool
		setting  string
		enrolled bool
		path     string
		wantLoc  string
	}{
		{name: "config on, not enrolled, /", cfgOn: true, path: "/", wantLoc: "/mfa/setup?required=1"},
		{name: "config on, not enrolled, /sessions", cfgOn: true, path: "/sessions", wantLoc: "/mfa/setup?required=1"},
		{name: "config on, not enrolled, /admin", cfgOn: true, path: "/admin", wantLoc: "/mfa/setup?required=1"},
		{name: "config on, enrolled, /", cfgOn: true, enrolled: true, path: "/"},
		{name: "config off, not enrolled, /", cfgOn: false, path: "/"},
		{name: "setting true overrides config off", setting: "true", path: "/", wantLoc: "/mfa/setup?required=1"},
		{name: "setting false overrides config on", cfgOn: true, setting: "false", path: "/"},
		{name: "setting true but enrolled", setting: "true", enrolled: true, path: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFullHandlerFixtureWith(t, true, func(c *config.Config) {
				c.Auth.RequireMFA = tt.cfgOn
			}, noopSender{})
			if tt.setting != "" {
				f.settings.values[user.SettingRequireMFA] = tt.setting
			}
			u := registerUser(t, f, "wendy")
			if tt.enrolled {
				enrollMFA(t, f, u)
			}
			token := sessionFor(t, f, u.ID)
			router := buildGatedRouter(f)

			rec := getWithSession(router, f, tt.path, token)
			loc := rec.Result().Header.Get("Location")
			if loc != tt.wantLoc {
				t.Fatalf("%s: Location = %q; want %q", tt.path, loc, tt.wantLoc)
			}
			if tt.wantLoc == "" && rec.Result().StatusCode != http.StatusOK {
				t.Errorf("%s: status = %d; want 200", tt.path, rec.Result().StatusCode)
			}
		})
	}
}

// TestRequireMFA_ExemptRoutesStayReachable proves the gate never traps a user:
// the enrollment page and logout work while the policy is on.
func TestRequireMFA_ExemptRoutesStayReachable(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixtureWith(t, true, func(c *config.Config) { c.Auth.RequireMFA = true }, noopSender{})
	u := registerUser(t, f, "xena")
	token := sessionFor(t, f, u.ID)
	router := buildGatedRouter(f)

	rec := getWithSession(router, f, "/mfa/setup?required=1", token)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("/mfa/setup status = %d; want 200", rec.Result().StatusCode)
	}
	if !strings.Contains(rec.Body.String(), "otpauth://totp/") {
		t.Error("/mfa/setup did not render the enrollment page")
	}

	// Enrolling satisfies the gate for the same session, immediately.
	var secret string
	if err := f.db.QueryRow(`SELECT secret FROM user_mfa WHERE user_id = ?`, u.ID).Scan(&secret); err != nil {
		t.Fatalf("read pending secret: %v", err)
	}
	form := url.Values{}
	form.Set("code", totpAt(t, secret, f.clock.Now()))
	req := httptest.NewRequest(http.MethodPost, "/mfa/setup", strings.NewReader(form.Encode()))
	req.AddCookie(&http.Cookie{Name: f.cfg.Session.CookieName, Value: token})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	router.ServeHTTP(postRec, req)
	if postRec.Result().StatusCode != http.StatusOK {
		t.Fatalf("enrollment POST status = %d; want 200", postRec.Result().StatusCode)
	}

	if rec := getWithSession(router, f, "/", token); rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("after enrollment, / status = %d; want 200", rec.Result().StatusCode)
	}

	// Logout is outside the session group entirely and must never redirect to
	// /mfa/setup.
	rec = getWithSession(router, f, "/logout", token)
	if loc := rec.Result().Header.Get("Location"); loc != "/login" {
		t.Fatalf("/logout Location = %q; want /login", loc)
	}
}

// TestMFALogin_BadCodesLockTheAccount proves the second step cannot be brute
// forced: repeated bad codes use the same per-account throttle as passwords.
func TestMFALogin_BadCodesLockTheAccount(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixtureWithThrottle(t, true, 3, 15)
	u := registerUser(t, f, "bruteforce")
	codes := enrollMFA(t, f, u)

	rec := postLogin(t, f, "bruteforce", "password123")
	token := challengeTokenFrom(t, f, rec)
	if token == "" {
		t.Fatal("no challenge issued")
	}

	for i := 0; i < 3; i++ {
		postMFALogin(t, f, token, "000000")
	}

	// Even a valid unused recovery code is refused while the account is locked.
	locked := postMFALogin(t, f, token, codes[0])
	if locked.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (re-rendered form)", locked.Code)
	}
	if !strings.Contains(locked.Body.String(), "Too many failed attempts") {
		t.Errorf("locked form does not show the throttle message")
	}
	if n := countSessions(t, f, u.ID); n != 0 {
		t.Errorf("session created while locked: %d", n)
	}
}

// TestMFALogin_SuccessResetsThrottle is the other half: a good code clears a
// partial failure count, so a fumbled digit does not accumulate.
func TestMFALogin_SuccessResetsThrottle(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixtureWithThrottle(t, true, 3, 15)
	u := registerUser(t, f, "fumbler")
	codes := enrollMFA(t, f, u)

	rec := postLogin(t, f, "fumbler", "password123")
	token := challengeTokenFrom(t, f, rec)

	for i := 0; i < 2; i++ {
		postMFALogin(t, f, token, "000000")
	}
	ok := postMFALogin(t, f, token, codes[0])
	if ok.Code != http.StatusFound {
		t.Fatalf("status = %d; want 302 after a valid recovery code", ok.Code)
	}
	if n := countSessions(t, f, u.ID); n != 1 {
		t.Errorf("sessions = %d; want 1", n)
	}
	if status, err := f.throttle.Status(context.Background(), "fumbler"); err != nil {
		t.Fatalf("throttle status: %v", err)
	} else if status.Failures != 0 {
		t.Errorf("failure counter = %d; want 0 after success", status.Failures)
	}
}
