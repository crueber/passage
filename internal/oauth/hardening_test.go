package oauth_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/db"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// issueTokens runs the real authorize + code-exchange flow and returns a fresh
// token set for the stack's seeded app and user.
func issueTokens(t *testing.T, stack *handlerTestStack, clientID, plainSecret, redirectURI, userID string) *oauth.TokenResponse {
	t.Helper()
	ctx := context.Background()

	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid profile", "", "", "", "", "", time.Now(), userID, "127.0.0.1")
	if err != nil {
		t.Fatalf("issueTokens: Authorize: %v", err)
	}
	resp, err := stack.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "")
	if err != nil {
		t.Fatalf("issueTokens: ExchangeCode: %v", err)
	}
	return resp
}

// tamperJWT changes one base64url character of a JWT signature so the token no
// longer verifies but its payload is untouched.
func tamperJWT(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("tamperJWT: expected 3 JWT parts, got %d", len(parts))
	}
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	return parts[0] + "." + parts[1] + "." + string(sig)
}

// TestHandler_Logout covers RP-initiated logout: hint verification, exact
// post_logout_redirect_uri matching, session revocation, and cookie clearing.
func TestHandler_Logout(t *testing.T) {
	const (
		clientID      = "client-logout"
		plainSecret   = "logout-secret"
		redirectURI   = "https://rp.example.com/callback"
		postLogoutURI = "https://rp.example.com/logged-out"
		baseURL       = "https://auth.example.com"
	)

	tests := []struct {
		name string
		// method defaults to GET when empty.
		method string
		// params builds the query/form values from a freshly minted id_token.
		params func(t *testing.T, idToken string) url.Values
		// sessionErr makes the fake session store fail on revocation.
		sessionErr  error
		wantStatus  int
		wantLoc     string
		wantRevoked bool
	}{
		{
			name: "valid_hint_with_registered_uri",
			params: func(_ *testing.T, idToken string) url.Values {
				return url.Values{
					"id_token_hint":            {idToken},
					"post_logout_redirect_uri": {postLogoutURI},
					"state":                    {"rp-state"},
				}
			},
			wantStatus:  http.StatusFound,
			wantLoc:     postLogoutURI + "?state=rp-state",
			wantRevoked: true,
		},
		{
			name:   "valid_hint_without_redirect",
			params: func(_ *testing.T, idToken string) url.Values { return url.Values{"id_token_hint": {idToken}} },
			// No post_logout_redirect_uri: land on the server base URL.
			wantStatus:  http.StatusFound,
			wantLoc:     baseURL,
			wantRevoked: true,
		},
		{
			name: "unregistered_redirect_is_rejected",
			params: func(_ *testing.T, idToken string) url.Values {
				return url.Values{
					"id_token_hint":            {idToken},
					"post_logout_redirect_uri": {"https://evil.example.com/logged-out"},
				}
			},
			wantStatus:  http.StatusBadRequest,
			wantRevoked: false,
		},
		{
			name: "prefix_of_registered_uri_is_rejected",
			params: func(_ *testing.T, idToken string) url.Values {
				return url.Values{
					"id_token_hint":            {idToken},
					"post_logout_redirect_uri": {"https://rp.example.com/callback/extra"},
				}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "tampered_hint_is_rejected",
			params: func(t *testing.T, idToken string) url.Values {
				return url.Values{
					"id_token_hint":            {tamperJWT(t, idToken)},
					"post_logout_redirect_uri": {postLogoutURI},
				}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unsigned_hint_is_rejected",
			params: func(_ *testing.T, _ string) url.Values {
				return url.Values{
					"id_token_hint":            {"not-a-jwt"},
					"post_logout_redirect_uri": {postLogoutURI},
				}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "client_id_mismatch_is_rejected",
			params: func(_ *testing.T, idToken string) url.Values {
				return url.Values{
					"id_token_hint": {idToken},
					"client_id":     {"some-other-client"},
				}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:        "no_hint_redirects_to_base_url",
			params:      func(_ *testing.T, _ string) url.Values { return url.Values{} },
			wantStatus:  http.StatusFound,
			wantLoc:     baseURL,
			wantRevoked: true,
		},
		{
			name:   "post_form_works",
			method: http.MethodPost,
			params: func(_ *testing.T, idToken string) url.Values {
				return url.Values{
					"id_token_hint":            {idToken},
					"post_logout_redirect_uri": {postLogoutURI},
				}
			},
			wantStatus:  http.StatusFound,
			wantLoc:     postLogoutURI,
			wantRevoked: true,
		},
		{
			// An already-expired or already-revoked browser session must not
			// block logout: the cookie is still cleared and the user moves on.
			name:       "session_already_gone",
			params:     func(_ *testing.T, _ string) url.Values { return url.Values{} },
			sessionErr: session.ErrSessionNotFound,
			wantStatus: http.StatusFound,
			wantLoc:    baseURL,
		},
		{
			name:       "session_store_failure_is_500",
			params:     func(_ *testing.T, _ string) url.Values { return url.Values{} },
			sessionErr: errors.New("db down"),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI, postLogoutURI})
			testUser := &user.User{Username: "logout-user", Email: "logout@example.com", Name: "Logout User"}

			sv := &fakeSessionValidator{revokeErr: tc.sessionErr}
			stack := buildHandlerTestStack(t, sv, testApp, testUser)
			idTokens := issueTokens(t, stack, clientID, plainSecret, redirectURI, testUser.ID)

			router := newTestRouter(stack.handler)

			if tc.method == "" {
				tc.method = http.MethodGet
			}
			params := tc.params(t, idTokens.IDToken)

			var req *http.Request
			if tc.method == http.MethodPost {
				req = httptest.NewRequest(http.MethodPost, "/oauth/logout", strings.NewReader(params.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(http.MethodGet, "/oauth/logout?"+params.Encode(), nil)
			}
			req.AddCookie(&http.Cookie{Name: "passage_session", Value: "sess-logout"})

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}

			if tc.wantStatus == http.StatusFound {
				if loc := w.Header().Get("Location"); loc != tc.wantLoc {
					t.Errorf("Location: got %q, want %q", loc, tc.wantLoc)
				}
				// The session cookie must always be cleared on a successful logout.
				setCookie := w.Header().Get("Set-Cookie")
				if !strings.Contains(setCookie, "passage_session=") || !strings.Contains(setCookie, "Max-Age=0") {
					t.Errorf("Set-Cookie does not clear the session cookie: %q", setCookie)
				}
			}

			revoked := len(sv.revoked) > 0
			if revoked != tc.wantRevoked {
				t.Errorf("session revoked = %v, want %v (revoked: %v)", revoked, tc.wantRevoked, sv.revoked)
			}
			if tc.wantRevoked && len(sv.revoked) == 1 && sv.revoked[0] != "sess-logout" {
				t.Errorf("revoked token: got %q, want %q", sv.revoked[0], "sess-logout")
			}
		})
	}
}

// TestHandler_Revoke covers RFC 7009 revocation behaviour, including the
// requirement to answer 200 for tokens that do not exist.
func TestHandler_Revoke(t *testing.T) {
	const (
		clientID    = "client-revoke"
		plainSecret = "revoke-secret"
		redirectURI = "https://rp.example.com/callback"
	)

	type wantLookup struct {
		accessToken  string
		refreshToken string
	}

	tests := []struct {
		name string
		// authMode selects how client credentials are presented: "" is the
		// form body, "basic" uses HTTP Basic auth, "bad-secret" sends a wrong
		// secret, "none" omits client auth entirely.
		authMode  string
		tokenFrom string // "access" | "refresh" | a literal token value
		wantCode  int
		wantGone  wantLookup
	}{
		{
			name:      "revoke_access_token",
			tokenFrom: "access",
			wantCode:  http.StatusOK,
			wantGone:  wantLookup{accessToken: "issued"},
		},
		{
			name:      "revoke_refresh_token",
			tokenFrom: "refresh",
			wantCode:  http.StatusOK,
			wantGone:  wantLookup{refreshToken: "issued"},
		},
		{
			name:      "unknown_token_still_200",
			tokenFrom: "this-token-does-not-exist",
			wantCode:  http.StatusOK,
		},
		{
			name:      "wrong_client_secret_401",
			authMode:  "bad-secret",
			tokenFrom: "access",
			wantCode:  http.StatusUnauthorized,
		},
		{
			name:      "missing_client_auth_401",
			authMode:  "none",
			tokenFrom: "access",
			wantCode:  http.StatusUnauthorized,
		},
		{
			name:      "basic_auth_works",
			authMode:  "basic",
			tokenFrom: "access",
			wantCode:  http.StatusOK,
			wantGone:  wantLookup{accessToken: "issued"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
			testUser := &user.User{Username: "revoke-user", Email: "revoke@example.com", Name: "Revoke User"}
			sv := &fakeSessionValidator{}
			stack := buildHandlerTestStack(t, sv, testApp, testUser)
			tokens := issueTokens(t, stack, clientID, plainSecret, redirectURI, testUser.ID)

			router := newTestRouter(stack.handler)

			form := url.Values{
				"client_id":     {clientID},
				"client_secret": {plainSecret},
			}
			switch tc.tokenFrom {
			case "access":
				form.Set("token", tokens.AccessToken)
				form.Set("token_type_hint", "access_token")
			case "refresh":
				form.Set("token", tokens.RefreshToken)
				form.Set("token_type_hint", "refresh_token")
			default:
				form.Set("token", tc.tokenFrom)
			}

			var basicAuth bool
			switch tc.authMode {
			case "basic":
				basicAuth = true
				form.Del("client_id")
				form.Del("client_secret")
			case "bad-secret":
				form.Set("client_secret", "definitely-wrong")
			case "none":
				form.Del("client_id")
				form.Del("client_secret")
			}

			req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if basicAuth {
				req.SetBasicAuth(clientID, plainSecret)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantCode {
				t.Fatalf("status: got %d, want %d; body: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantCode == http.StatusOK && w.Body.Len() != 0 {
				t.Errorf("revocation response body should be empty, got %q", w.Body.String())
			}

			ctx := context.Background()
			switch {
			case tc.wantGone.accessToken == "issued":
				// JWT access tokens are stateless; revocation denylists the jti.
				if _, _, err := stack.svc.ValidateAccessToken(ctx, tokens.AccessToken); !errors.Is(err, oauth.ErrTokenRevoked) {
					t.Errorf("access token still usable after revocation: %v", err)
				}
			case tc.wantGone.refreshToken == "issued":
				if _, err := stack.store.GetRefreshToken(ctx, tokens.RefreshToken); !errors.Is(err, oauth.ErrRefreshNotFound) {
					t.Errorf("refresh token still present after revocation: %v", err)
				}
			case tc.wantCode == http.StatusUnauthorized:
				// A rejected request must not touch the token.
				if _, _, err := stack.svc.ValidateAccessToken(ctx, tokens.AccessToken); err != nil {
					t.Errorf("access token was revoked despite failed client auth: %v", err)
				}
			}
		})
	}
}

// TestHandler_Revoke_DeletesWholeFamily verifies that revoking a rotated
// refresh token removes its parent and every sibling too.
func TestHandler_Revoke_DeletesWholeFamily(t *testing.T) {
	const (
		clientID    = "client-revoke-family"
		plainSecret = "revoke-family-secret"
		redirectURI = "https://rp.example.com/callback"
	)

	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{Username: "family-user", Email: "family@example.com", Name: "Family User"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)

	first := issueTokens(t, stack, clientID, plainSecret, redirectURI, testUser.ID)
	ctx := context.Background()
	second, err := stack.svc.RefreshTokens(ctx, first.RefreshToken, clientID, plainSecret, "", "")
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}

	router := newTestRouter(stack.handler)
	form := url.Values{
		"token":         {second.RefreshToken},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("revoke: status %d, want 200; body: %s", w.Code, w.Body.String())
	}

	for name, token := range map[string]string{"parent": first.RefreshToken, "child": second.RefreshToken} {
		if _, err := stack.store.GetRefreshToken(ctx, token); !errors.Is(err, oauth.ErrRefreshNotFound) {
			t.Errorf("%s refresh token still present: %v", name, err)
		}
	}
}

// TestHandler_Introspect covers RFC 7662: active tokens expose metadata (never
// the token itself); everything else is {"active": false}.
func TestHandler_Introspect(t *testing.T) {
	const (
		clientID    = "client-introspect"
		plainSecret = "introspect-secret"
		redirectURI = "https://rp.example.com/callback"
	)

	tests := []struct {
		name string
		// pick returns the token to introspect and optional direct DB setup.
		pick          func(t *testing.T, stack *handlerTestStack, tokens *oauth.TokenResponse) string
		hint          string
		secret        string
		wantStatus    int
		wantActive    bool
		wantTokenType string
	}{
		{
			name:          "active_access_token",
			pick:          func(_ *testing.T, _ *handlerTestStack, tokens *oauth.TokenResponse) string { return tokens.AccessToken },
			wantStatus:    http.StatusOK,
			wantActive:    true,
			wantTokenType: "Bearer",
		},
		{
			name: "active_refresh_token",
			pick: func(_ *testing.T, _ *handlerTestStack, tokens *oauth.TokenResponse) string {
				return tokens.RefreshToken
			},
			wantStatus:    http.StatusOK,
			wantActive:    true,
			wantTokenType: "refresh_token",
		},
		{
			// The hint is advisory: a wrong hint must not hide a live token.
			name: "access_token_with_refresh_hint",
			pick: func(_ *testing.T, _ *handlerTestStack, tokens *oauth.TokenResponse) string {
				return tokens.AccessToken
			},
			hint:          "refresh_token",
			wantStatus:    http.StatusOK,
			wantActive:    true,
			wantTokenType: "Bearer",
		},
		{
			name: "expired_access_token",
			pick: func(t *testing.T, stack *handlerTestStack, _ *oauth.TokenResponse) string {
				t.Helper()
				expired := &oauth.Token{
					AppID:     stack.appID,
					UserID:    stack.userID,
					Scopes:    "openid",
					ExpiresAt: time.Now().UTC().Add(-time.Minute),
				}
				if err := stack.store.CreateToken(context.Background(), expired); err != nil {
					t.Fatalf("CreateToken: %v", err)
				}
				return expired.Token
			},
			wantStatus: http.StatusOK,
			wantActive: false,
		},
		{
			name: "revoked_access_token",
			pick: func(t *testing.T, stack *handlerTestStack, tokens *oauth.TokenResponse) string {
				t.Helper()
				if err := stack.svc.RevokeToken(context.Background(), tokens.AccessToken, "access_token", clientID, plainSecret); err != nil {
					t.Fatalf("RevokeToken: %v", err)
				}
				return tokens.AccessToken
			},
			wantStatus: http.StatusOK,
			wantActive: false,
		},
		{
			name: "used_refresh_token",
			pick: func(t *testing.T, stack *handlerTestStack, tokens *oauth.TokenResponse) string {
				t.Helper()
				if err := stack.store.MarkRefreshTokenUsed(context.Background(), tokens.RefreshToken); err != nil {
					t.Fatalf("MarkRefreshTokenUsed: %v", err)
				}
				return tokens.RefreshToken
			},
			wantStatus: http.StatusOK,
			wantActive: false,
		},
		{
			name:       "unknown_token",
			pick:       func(_ *testing.T, _ *handlerTestStack, _ *oauth.TokenResponse) string { return "no-such-token" },
			wantStatus: http.StatusOK,
			wantActive: false,
		},
		{
			name:       "wrong_client_secret_401",
			pick:       func(_ *testing.T, _ *handlerTestStack, tokens *oauth.TokenResponse) string { return tokens.AccessToken },
			secret:     "wrong-secret",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
			testUser := &user.User{Username: "introspect-user", Email: "introspect@example.com", Name: "Introspect User"}
			sv := &fakeSessionValidator{}
			stack := buildHandlerTestStack(t, sv, testApp, testUser)
			tokens := issueTokens(t, stack, clientID, plainSecret, redirectURI, testUser.ID)

			secret := plainSecret
			if tc.secret != "" {
				secret = tc.secret
			}

			router := newTestRouter(stack.handler)
			form := url.Values{
				"token":         {tc.pick(t, stack, tokens)},
				"client_id":     {clientID},
				"client_secret": {secret},
			}
			if tc.hint != "" {
				form.Set("token_type_hint", tc.hint)
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return
			}

			var body map[string]any
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}

			active, _ := body["active"].(bool)
			if active != tc.wantActive {
				t.Fatalf("active: got %v, want %v (body: %v)", active, tc.wantActive, body)
			}

			// The token value must never be echoed in any response.
			if strings.Contains(w.Body.String(), form.Get("token")) {
				t.Errorf("introspection response leaked the token value: %s", w.Body.String())
			}

			if !tc.wantActive {
				if len(body) != 1 {
					t.Errorf("inactive response must contain only active:false, got %v", body)
				}
				return
			}

			for _, field := range []string{"client_id", "username", "sub", "scope", "exp", "iat", "token_type"} {
				if _, ok := body[field]; !ok {
					t.Errorf("active response missing %q: %v", field, body)
				}
			}
			if body["client_id"] != clientID {
				t.Errorf("client_id: got %v, want %q", body["client_id"], clientID)
			}
			if body["sub"] != testUser.ID {
				t.Errorf("sub: got %v, want %q", body["sub"], testUser.ID)
			}
			if body["token_type"] != tc.wantTokenType {
				t.Errorf("token_type: got %v, want %q", body["token_type"], tc.wantTokenType)
			}
			exp, _ := body["exp"].(float64)
			iat, _ := body["iat"].(float64)
			if exp <= iat {
				t.Errorf("exp (%v) must be after iat (%v)", exp, iat)
			}
		})
	}
}

// TestHandler_Introspect_MissingClientAuth verifies introspection refuses
// unauthenticated callers rather than leaking token state.
func TestHandler_Introspect_MissingClientAuth(t *testing.T) {
	testApp := buildTestApp(t, "client-introspect-noauth", "secret", []string{"https://rp.example.com/cb"})
	testUser := &user.User{Username: "noauth", Email: "noauth@example.com", Name: "No Auth"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)

	router := newTestRouter(stack.handler)
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader("token=anything"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401; body: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "active") {
		t.Errorf("unauthenticated introspection must not report token state: %s", w.Body.String())
	}
}

// TestHandler_RefreshTokenReuse_RevokesFamily drives reuse detection through
// the token endpoint: rotate once, replay the old token, and confirm the whole
// family is gone so the sibling token stops working too.
func TestHandler_RefreshTokenReuse_RevokesFamily(t *testing.T) {
	const (
		clientID    = "client-reuse"
		plainSecret = "reuse-secret"
		redirectURI = "https://rp.example.com/callback"
	)

	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{Username: "reuse-user", Email: "reuse@example.com", Name: "Reuse User"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)

	ctx := context.Background()
	tokens := issueTokens(t, stack, clientID, plainSecret, redirectURI, testUser.ID)

	firstRT, err := stack.store.GetRefreshToken(ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if firstRT.FamilyID == "" {
		t.Fatal("first refresh token has no family_id")
	}

	// Rotate once: child must inherit the family.
	rotated, err := stack.svc.RefreshTokens(ctx, tokens.RefreshToken, clientID, plainSecret, "", "")
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	secondRT, err := stack.store.GetRefreshToken(ctx, rotated.RefreshToken)
	if err != nil {
		t.Fatalf("GetRefreshToken (child): %v", err)
	}
	if secondRT.FamilyID != firstRT.FamilyID {
		t.Fatalf("child family_id: got %q, want %q", secondRT.FamilyID, firstRT.FamilyID)
	}

	// Replay the consumed parent token.
	router := newTestRouter(stack.handler)
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("replay: status %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var errBody map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBody["error"] != "invalid_grant" {
		t.Errorf("replay error: got %q, want invalid_grant", errBody["error"])
	}

	// Whole family must be gone: parent and sibling.
	for name, token := range map[string]string{"parent": tokens.RefreshToken, "sibling": rotated.RefreshToken} {
		if _, err := stack.store.GetRefreshToken(ctx, token); !errors.Is(err, oauth.ErrRefreshNotFound) {
			t.Errorf("%s refresh token still present after reuse: %v", name, err)
		}
	}
	var count int
	if err := stack.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE family_id = ?`, firstRT.FamilyID,
	).Scan(&count); err != nil {
		t.Fatalf("count family rows: %v", err)
	}
	if count != 0 {
		t.Errorf("family still has %d token rows after reuse detection", count)
	}

	// The surviving sibling token no longer works either.
	rotatedForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotated.RefreshToken},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(rotatedForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("sibling after reuse: status %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

// TestService_RefreshTokenReuse_ErrorType verifies the typed error exposes the
// family identity for event emission without carrying token material.
func TestService_RefreshTokenReuse_ErrorType(t *testing.T) {
	const (
		clientID    = "client-reuse-service"
		plainSecret = "reuse-service-secret"
		redirectURI = "https://rp.example.com/callback"
	)

	db := testutil.NewTestDB(t)
	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{Username: "reuse2", Email: "reuse2@example.com", Name: "Reuse Two"}
	sc := newTestServiceWithDB(t, db, testApp, testUser)

	ctx := context.Background()
	code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", "", "", "", "", time.Now(), testUser.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	tokens, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if _, err := sc.svc.RefreshTokens(ctx, tokens.RefreshToken, clientID, plainSecret, "", ""); err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}

	_, err = sc.svc.RefreshTokens(ctx, tokens.RefreshToken, clientID, plainSecret, "", "")
	if err == nil {
		t.Fatal("replay: expected an error, got nil")
	}
	var reuseErr *oauth.RefreshTokenReuseError
	if !errors.As(err, &reuseErr) {
		t.Fatalf("replay error is %T (%v), want *RefreshTokenReuseError", err, err)
	}
	if !errors.Is(err, oauth.ErrRefreshTokenReuse) {
		t.Error("reuse error does not match ErrRefreshTokenReuse")
	}
	// Existing callers still see the "already used" sentinel.
	if !errors.Is(err, oauth.ErrRefreshUsed) {
		t.Error("reuse error does not match ErrRefreshUsed")
	}
	if reuseErr.AppID != sc.appID {
		t.Errorf("reuse AppID: got %q, want %q", reuseErr.AppID, sc.appID)
	}
	if reuseErr.UserID != sc.userID {
		t.Errorf("reuse UserID: got %q, want %q", reuseErr.UserID, sc.userID)
	}
	if reuseErr.FamilyID == "" {
		t.Error("reuse FamilyID is empty")
	}
	if strings.Contains(err.Error(), tokens.RefreshToken) {
		t.Error("reuse error message contains the token value")
	}
}

// TestMigration016_RefreshFamilySafeOnPopulatedDB proves migration 016 is safe
// on a database that already holds refresh tokens: simulating a pre-016 schema,
// re-applying the migration keeps every row intact and backfills family_id.
func TestMigration016_RefreshFamilySafeOnPopulatedDB(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "passage.db")

	database, err := db.Open(ctx, dbPath, slog.Default())
	if err != nil {
		t.Fatalf("db.Open (initial): %v", err)
	}

	appID, userID := seedAppAndUser(t, database)

	type row struct {
		token     string
		expiresAt time.Time
	}
	rows := []row{
		{token: "pre016-token-one", expiresAt: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)},
		{token: "pre016-token-two", expiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)},
	}
	for _, r := range rows {
		_, err := database.ExecContext(ctx, `
			INSERT INTO oauth_refresh_tokens (token, app_id, user_id, scopes, expires_at, created_at, updated_at)
			VALUES (?, ?, ?, 'openid profile', ?, ?, ?)`,
			r.token, appID, userID, r.expiresAt, time.Now().UTC(), time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert pre-016 refresh token: %v", err)
		}
	}

	// Simulate the schema as it existed before migration 016, then forget that
	// goose applied 016 so reopening the DB runs it against these rows.
	if _, err := database.ExecContext(ctx, `DROP INDEX IF EXISTS oauth_refresh_tokens_family`); err != nil {
		t.Fatalf("drop family index: %v", err)
	}
	if _, err := database.ExecContext(ctx, `ALTER TABLE oauth_refresh_tokens DROP COLUMN family_id`); err != nil {
		t.Fatalf("drop family_id column: %v", err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM goose_db_version WHERE version_id = 16`); err != nil {
		t.Fatalf("forget migration version: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close initial DB: %v", err)
	}

	// Re-open twice: the migration applies once, then a restart must be a no-op.
	for attempt := 0; attempt < 2; attempt++ {
		database, err = db.Open(ctx, dbPath, slog.Default())
		if err != nil {
			t.Fatalf("db.Open (attempt %d): %v", attempt+1, err)
		}

		for _, r := range rows {
			var (
				gotAppID, gotUserID, gotScopes, gotFamilyID string
				gotExpires                                  time.Time
				usedAt                                      sql.NullTime
				createdAt                                   time.Time
			)
			err := database.QueryRowContext(ctx, `
				SELECT app_id, user_id, scopes, expires_at, used_at, created_at, family_id
				FROM oauth_refresh_tokens WHERE token = ?`, r.token,
			).Scan(&gotAppID, &gotUserID, &gotScopes, &gotExpires, &usedAt, &createdAt, &gotFamilyID)
			if err != nil {
				t.Fatalf("attempt %d: read back %q: %v", attempt+1, r.token, err)
			}
			if gotAppID != appID || gotUserID != userID {
				t.Errorf("attempt %d: %q ownership changed: app=%q user=%q", attempt+1, r.token, gotAppID, gotUserID)
			}
			if gotScopes != "openid profile" {
				t.Errorf("attempt %d: %q scopes changed: %q", attempt+1, r.token, gotScopes)
			}
			if !gotExpires.Equal(r.expiresAt) {
				t.Errorf("attempt %d: %q expires_at changed: got %v, want %v", attempt+1, r.token, gotExpires, r.expiresAt)
			}
			if usedAt.Valid {
				t.Errorf("attempt %d: %q used_at changed: %v", attempt+1, r.token, usedAt.Time)
			}
			if gotFamilyID != r.token {
				t.Errorf("attempt %d: %q family_id: got %q, want backfilled token value", attempt+1, r.token, gotFamilyID)
			}
		}

		// The family index must exist after the migration.
		var indexName string
		if err := database.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'oauth_refresh_tokens_family'`,
		).Scan(&indexName); err != nil {
			t.Errorf("attempt %d: family index missing: %v", attempt+1, err)
		}

		if err := database.Close(); err != nil {
			t.Fatalf("attempt %d: close DB: %v", attempt+1, err)
		}
	}
}
