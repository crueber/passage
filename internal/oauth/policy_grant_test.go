package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// policyGrantStack builds an authorizing stack whose app starts with no policy,
// so a test can add one in the middle of a token lifecycle.
func policyGrantStack(t *testing.T, clientID, plainSecret, redirectURI string) (*handlerTestStack, *user.User) {
	t.Helper()
	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{Username: "dana", Email: "dana@example.com", Name: "Dana"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	testUser.IsActive = true
	stack.apps.app.Slug = "policy-app"
	return stack, testUser
}

// TestService_ExchangeCode_RechecksAccessPolicy proves an access policy added
// between authorize and the token request stops the code: no token is issued,
// and the denial reports the same rule an authorize-time denial would.
func TestService_ExchangeCode_RechecksAccessPolicy(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-policy-exchange"
		plainSecret = "policy-exchange-secret"
		redirectURI = "https://rp.example.com/cb"
	)
	ctx := context.Background()
	stack, testUser := policyGrantStack(t, clientID, plainSecret, redirectURI)

	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "", "", "", "", "", time.Now(), testUser.ID, "10.0.0.5")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// The administrator tightens the app while the code is outstanding.
	stack.apps.app.RequiredGroup = "platform"

	resp, err := stack.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "", "10.0.0.5")
	if err == nil {
		t.Fatalf("ExchangeCode succeeded after the policy was added; token = %+v", resp)
	}
	if !errors.Is(err, oauth.ErrAccessDeniedByPolicy) {
		t.Fatalf("ExchangeCode error = %v, want ErrAccessDeniedByPolicy", err)
	}
	var denial *oauth.PolicyDenialError
	if !errors.As(err, &denial) {
		t.Fatalf("ExchangeCode error = %v, want *PolicyDenialError", err)
	}
	if denial.Reason != "group" {
		t.Errorf("denial reason = %q, want %q", denial.Reason, "group")
	}
	if denial.UserID != testUser.ID || denial.Username != testUser.Username {
		t.Errorf("denial user = (%q, %q), want (%q, %q)",
			denial.UserID, denial.Username, testUser.ID, testUser.Username)
	}

}

// TestService_RefreshTokens_RechecksAccessPolicy proves a refresh chain cannot
// outlive a policy added after it started: the refresh is refused, the chain is
// burned rather than left usable, and lifting the policy does not revive it.
func TestService_RefreshTokens_RechecksAccessPolicy(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-policy-refresh"
		plainSecret = "policy-refresh-secret"
		redirectURI = "https://rp.example.com/cb"
	)
	ctx := context.Background()
	stack, testUser := policyGrantStack(t, clientID, plainSecret, redirectURI)

	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "", "", "", "", "", time.Now(), testUser.ID, "10.0.0.5")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	first, err := stack.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "", "10.0.0.5")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if first.RefreshToken == "" {
		t.Fatal("no refresh token issued")
	}

	// A policy arrives while the client holds a live refresh token.
	stack.apps.app.RequiredGroup = "platform"

	second, err := stack.svc.RefreshTokens(ctx, first.RefreshToken, clientID, plainSecret, "", "", "10.0.0.5")
	if err == nil {
		t.Fatalf("RefreshTokens succeeded after the policy was added; token = %+v", second)
	}
	if !errors.Is(err, oauth.ErrAccessDeniedByPolicy) {
		t.Fatalf("RefreshTokens error = %v, want ErrAccessDeniedByPolicy", err)
	}

	// The denied refresh rotated the token, so even a policy that is lifted
	// afterwards cannot revive the chain with the same value.
	stack.apps.app.RequiredGroup = ""
	if _, err := stack.svc.RefreshTokens(ctx, first.RefreshToken, clientID, plainSecret, "", "", "10.0.0.5"); err == nil {
		t.Fatal("a refresh token burned by a policy denial was still usable")
	}
}

// TestHandler_Token_PolicyDenial pins the wire behaviour of a policy denial at
// the token endpoint: invalid_grant (not server_error), and an access.denied
// event that names the app and rule but never appears in the response.
func TestHandler_Token_PolicyDenial(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-policy-token"
		plainSecret = "policy-token-secret"
		redirectURI = "https://rp.example.com/cb"
	)
	stack, testUser := policyGrantStack(t, clientID, plainSecret, redirectURI)

	sv := &fakeSessionValidator{
		sess: &session.Session{ID: "sess-policy-token", UserID: testUser.ID, CreatedAt: time.Now()},
		u:    testUser,
	}
	recorder := &policyRecorder{}
	h := oauth.NewHandler(stack.svc, sv, "https://auth.example.com", recorder, testConfig(), discardLogger())
	router := newTestRouter(h)

	authorizeURL := "/oauth/authorize?client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(redirectURI) + "&response_type=code&scope=openid&state=st"
	req := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	req.AddCookie(&http.Cookie{Name: "passage_session", Value: "session-token"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302; body: %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", loc.String())
	}

	stack.apps.app.AdminOnly = true // a non-admin user is now refused

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("token status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", body["error"])
	}
	if strings.Contains(strings.ToLower(body["error_description"]), "admin") {
		t.Errorf("error_description leaks the rule: %q", body["error_description"])
	}

	ev := recorder.last()
	if ev.Event != authlog.EventAccessDenied {
		t.Fatalf("event = %q, want %q", ev.Event, authlog.EventAccessDenied)
	}
	if ev.UserID != testUser.ID {
		t.Errorf("event user = %q, want %q", ev.UserID, testUser.ID)
	}
	if want := "app=policy-app"; !strings.Contains(ev.Detail, want) {
		t.Errorf("event detail = %q, want it to contain %q", ev.Detail, want)
	}
	if want := "reason=admin_only"; !strings.Contains(ev.Detail, want) {
		t.Errorf("event detail = %q, want it to contain %q", ev.Detail, want)
	}

}
