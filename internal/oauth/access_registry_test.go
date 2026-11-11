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

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// accessAudience decodes an access token without verifying it, for assertions
// about the audience. The signature is checked elsewhere.
func accessAudience(t *testing.T, raw string) string {
	t.Helper()
	claims := jwtlib.MapClaims{}
	if _, _, err := jwtlib.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	aud, err := claims.GetAudience()
	if err != nil || len(aud) == 0 {
		t.Fatalf("aud claim: %v (audience=%v)", err, aud)
	}
	return aud[0]
}

// TestService_ScopeRegistry pins the scope registry semantics: an empty
// registry grants whatever is requested, and a configured one refuses any
// escalation with invalid_scope before a code or token exists.
func TestService_ScopeRegistry(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-scope-registry"
		plainSecret = "scope-registry-secret"
		redirectURI = "https://rp.example.com/callback"
	)
	ctx := context.Background()

	tests := []struct {
		name     string
		registry []string
		request  string
		wantErr  error
		want     string
	}{
		{name: "empty registry keeps old behaviour", registry: nil, request: "openid profile", want: "openid profile"},
		{name: "requested subset is allowed", registry: []string{"openid", "profile", "email"}, request: "openid profile", want: "openid profile"},
		{name: "escalation is refused", registry: []string{"openid"}, request: "openid admin", wantErr: oauth.ErrInvalidScope},
		{name: "openid must be registered", registry: []string{"profile"}, request: "openid", wantErr: oauth.ErrInvalidScope},
		{name: "empty request defaults to openid", registry: []string{"openid"}, request: "", want: "openid"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
			testApp.AllowedScopes = tc.registry
			testUser := &user.User{Username: "scope-user", Email: "scope@example.com", Name: "Scope User"}
			sc := newTestServiceWithDB(t, testutil.NewTestDB(t), testApp, testUser)

			code, err := sc.svc.Authorize(ctx, clientID, redirectURI, tc.request, "", "", "", "", "", time.Now(), testUser.ID, "127.0.0.1")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Authorize error = %v, want %v", err, tc.wantErr)
				}
				if code != nil {
					t.Fatal("a code was issued for a refused scope")
				}
				return
			}
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}

			resp, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "")
			if err != nil {
				t.Fatalf("ExchangeCode: %v", err)
			}
			if resp.Scope != tc.want {
				t.Errorf("granted scope = %q, want %q", resp.Scope, tc.want)
			}
			claims := jwtlib.MapClaims{}
			if _, _, err := jwtlib.NewParser().ParseUnverified(resp.AccessToken, claims); err != nil {
				t.Fatalf("parse access token: %v", err)
			}
			if got, _ := claims.GetSubject(); got == "" {
				t.Error("access token has no sub")
			}
			if scope, _ := claims["scope"].(string); scope != tc.want {
				t.Errorf("access token scope claim = %q, want %q", scope, tc.want)
			}
		})
	}
}

// TestService_ResourceIndicator pins RFC 8707 handling at authorize and token
// time: a registered resource becomes the audience, anything else is
// invalid_target and issues nothing.
func TestService_ResourceIndicator(t *testing.T) {
	t.Parallel()
	const (
		clientID      = "client-resource"
		plainSecret   = "resource-secret"
		redirectURI   = "https://rp.example.com/callback"
		resource      = "https://api.example.com"
		otherResource = "https://other.example.com"
	)
	ctx := context.Background()

	tests := []struct {
		name       string
		registry   []string
		authorize  string
		exchange   string
		wantErr    error
		wantAud    string
		wantNoCode bool
	}{
		{
			name:      "registered resource becomes the audience",
			registry:  []string{resource},
			authorize: resource,
			wantAud:   resource,
		},
		{
			name:      "echoed resource is accepted",
			registry:  []string{resource},
			authorize: resource,
			exchange:  resource,
			wantAud:   resource,
		},
		{
			name:       "unregistered resource is refused",
			registry:   []string{resource},
			authorize:  otherResource,
			wantErr:    oauth.ErrInvalidTarget,
			wantNoCode: true,
		},
		{
			name:       "resource with no registry is refused",
			authorize:  resource,
			wantErr:    oauth.ErrInvalidTarget,
			wantNoCode: true,
		},
		{
			name:       "relative resource is refused",
			registry:   []string{resource},
			authorize:  "api.example.com",
			wantErr:    oauth.ErrInvalidTarget,
			wantNoCode: true,
		},
		{
			name:     "no resource keeps the client audience",
			registry: []string{resource},
			wantAud:  clientID,
			wantErr:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
			testApp.AllowedResources = tc.registry
			testUser := &user.User{Username: "resource-user", Email: "resource@example.com", Name: "Resource User"}
			sc := newTestServiceWithDB(t, testutil.NewTestDB(t), testApp, testUser)

			code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", tc.authorize, "", "", "", "", time.Now(), testUser.ID, "127.0.0.1")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Authorize error = %v, want %v", err, tc.wantErr)
				}
				if tc.wantNoCode && code != nil {
					t.Fatal("a code was issued for a refused resource")
				}
				return
			}
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}

			resp, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", tc.exchange)
			if err != nil {
				t.Fatalf("ExchangeCode: %v", err)
			}
			if got := accessAudience(t, resp.AccessToken); got != tc.wantAud {
				t.Errorf("aud = %q, want %q", got, tc.wantAud)
			}
		})
	}
}

// TestService_ExchangeCode_ResourceMismatch proves the token endpoint cannot
// be talked into a different audience from the one the user approved.
func TestService_ExchangeCode_ResourceMismatch(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-resource-mismatch"
		plainSecret = "resource-mismatch-secret"
		redirectURI = "https://rp.example.com/callback"
		resource    = "https://api.example.com"
	)
	ctx := context.Background()

	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testApp.AllowedResources = []string{resource, "https://other.example.com"}
	testUser := &user.User{Username: "mismatch-user", Email: "mismatch@example.com", Name: "Mismatch User"}
	sc := newTestServiceWithDB(t, testutil.NewTestDB(t), testApp, testUser)

	code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", resource, "", "", "", "", time.Now(), testUser.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	_, err = sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "https://other.example.com")
	if !errors.Is(err, oauth.ErrInvalidTarget) {
		t.Errorf("ExchangeCode with a different resource = %v, want ErrInvalidTarget", err)
	}
}

// TestService_RefreshToken_ScopeAndResource pins refresh-grant narrowing and
// audience selection.
func TestService_RefreshToken_ScopeAndResource(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-refresh-registry"
		plainSecret = "refresh-registry-secret"
		redirectURI = "https://rp.example.com/callback"
		resource    = "https://api.example.com"
	)
	ctx := context.Background()

	tests := []struct {
		name      string
		registry  []string
		scope     string
		resource  string
		wantErr   error
		wantScope string
		wantAud   string
	}{
		{name: "no registry, inherited scope", registry: nil, wantScope: "openid profile", wantAud: clientID},
		{name: "narrowed scope is allowed", registry: []string{"openid", "profile"}, scope: "openid", wantScope: "openid", wantAud: clientID},
		{name: "widened scope is refused", registry: []string{"openid", "profile"}, scope: "openid email", wantErr: oauth.ErrInvalidScope},
		{name: "resource is accepted", registry: []string{"openid", "profile"}, resource: resource, wantScope: "openid profile", wantAud: resource},
		{name: "unregistered resource is refused", registry: []string{"openid", "profile"}, resource: "https://evil.example.com", wantErr: oauth.ErrInvalidTarget},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
			testApp.AllowedScopes = tc.registry
			testApp.AllowedResources = []string{resource}
			testUser := &user.User{Username: "refresh-user", Email: "refresh@example.com", Name: "Refresh User"}
			sc := newTestServiceWithDB(t, testutil.NewTestDB(t), testApp, testUser)

			code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid profile", "", "", "", "", "", time.Now(), testUser.ID, "127.0.0.1")
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			first, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "")
			if err != nil {
				t.Fatalf("ExchangeCode: %v", err)
			}

			resp, err := sc.svc.RefreshTokens(ctx, first.RefreshToken, clientID, plainSecret, tc.resource, tc.scope)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("RefreshTokens error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("RefreshTokens: %v", err)
			}
			if resp.Scope != tc.wantScope {
				t.Errorf("scope = %q, want %q", resp.Scope, tc.wantScope)
			}
			if got := accessAudience(t, resp.AccessToken); got != tc.wantAud {
				t.Errorf("aud = %q, want %q", got, tc.wantAud)
			}
		})
	}
}

// TestService_OpaqueAccessTokenStillWorks proves a token already stored in
// oauth_tokens (issued before JWTs existed) still validates and introspects,
// so an upgrade never forces a re-login.
func TestService_OpaqueAccessTokenStillWorks(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-opaque"
		plainSecret = "opaque-secret"
		redirectURI = "https://rp.example.com/callback"
	)
	ctx := context.Background()

	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{Username: "opaque-user", Email: "opaque@example.com", Name: "Opaque User"}
	sc := newTestServiceWithDB(t, testutil.NewTestDB(t), testApp, testUser)

	opaque := &oauth.Token{
		AppID:     sc.appID,
		UserID:    sc.userID,
		Scopes:    "openid profile",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := sc.store.CreateToken(ctx, opaque); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	u, tok, err := sc.svc.ValidateAccessToken(ctx, opaque.Token)
	if err != nil {
		t.Fatalf("ValidateAccessToken(opaque): %v", err)
	}
	if u.ID != sc.userID || tok.Token != opaque.Token || tok.AppID != sc.appID {
		t.Errorf("opaque validation = user %q token %q app %q", u.ID, tok.Token, tok.AppID)
	}

	info, err := sc.svc.IntrospectToken(ctx, opaque.Token, "access_token", clientID, plainSecret)
	if err != nil {
		t.Fatalf("IntrospectToken(opaque): %v", err)
	}
	if info == nil || !info.Active || info.Scope != "openid profile" || info.Audience != clientID {
		t.Errorf("opaque introspection = %+v, want active scope openid profile aud %s", info, clientID)
	}
}

// TestService_JWTIntrospectionAndRevocation proves both introspection and
// userinfo reject a denylisted JWT.
func TestService_JWTIntrospectionAndRevocation(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-jwt-revoke"
		plainSecret = "jwt-revoke-secret"
		redirectURI = "https://rp.example.com/callback"
	)
	ctx := context.Background()

	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{Username: "jwt-revoke-user", Email: "jwt-revoke@example.com", Name: "JWT Revoke User"}
	sc := newTestServiceWithDB(t, testutil.NewTestDB(t), testApp, testUser)

	code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid profile", "", "", "", "", "", time.Now(), testUser.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	tokens, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	info, err := sc.svc.IntrospectToken(ctx, tokens.AccessToken, "access_token", clientID, plainSecret)
	if err != nil {
		t.Fatalf("IntrospectToken before revoke: %v", err)
	}
	if info == nil || !info.Active || info.TokenType != "Bearer" || info.Audience != clientID {
		t.Fatalf("live JWT introspection = %+v", info)
	}

	if err := sc.svc.RevokeToken(ctx, tokens.AccessToken, "access_token", clientID, plainSecret); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	if _, _, err := sc.svc.ValidateAccessToken(ctx, tokens.AccessToken); !errors.Is(err, oauth.ErrTokenRevoked) {
		t.Errorf("ValidateAccessToken after revoke = %v, want ErrTokenRevoked", err)
	}
	info, err = sc.svc.IntrospectToken(ctx, tokens.AccessToken, "access_token", clientID, plainSecret)
	if err != nil {
		t.Fatalf("IntrospectToken after revoke: %v", err)
	}
	if info != nil {
		t.Errorf("revoked JWT introspects active: %+v", info)
	}
}

// TestHandler_UserInfo_RevokedAndForgedJWT pins userinfo's rejection of a
// denylisted token and of an `alg: none` forgery.
func TestHandler_UserInfo_RevokedAndForgedJWT(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-userinfo-jwt"
		plainSecret = "userinfo-jwt-secret"
		redirectURI = "https://rp.example.com/callback"
	)

	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{Username: "userinfo-jwt", Email: "userinfo-jwt@example.com", Name: "UserInfo JWT"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	tokens := issueTokens(t, stack, clientID, plainSecret, redirectURI, testUser.ID)
	router := newTestRouter(stack.handler)

	userinfo := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	if got := userinfo(tokens.AccessToken); got != http.StatusOK {
		t.Fatalf("live token userinfo = %d, want 200", got)
	}

	if err := stack.svc.RevokeToken(context.Background(), tokens.AccessToken, "access_token", clientID, plainSecret); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if got := userinfo(tokens.AccessToken); got != http.StatusUnauthorized {
		t.Errorf("revoked token userinfo = %d, want 401", got)
	}

	forged := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, jwtlib.MapClaims{
		"iss":       "https://auth.example.com",
		"sub":       testUser.ID,
		"aud":       jwtlib.ClaimStrings{clientID},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       "forged",
		"scope":     "openid",
		"client_id": clientID,
	})
	forged.Header["kid"] = "whatever"
	raw, err := forged.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}
	if got := userinfo(raw); got != http.StatusUnauthorized {
		t.Errorf("alg=none token userinfo = %d, want 401", got)
	}
}

// TestHandler_Authorize_ScopeAndResource pins the HTTP contract for the scope
// registry and resource indicators: an escalation or an unregistered audience
// is a 400 with the RFC error code and no code is issued; a registered one is
// carried through the request into the token.
func TestHandler_Authorize_ScopeAndResource(t *testing.T) {
	t.Parallel()
	const (
		clientID    = "client-authorize-registry"
		plainSecret = "authorize-registry-secret"
		redirectURI = "https://rp.example.com/callback"
		resource    = "https://api.example.com"
	)

	type want struct {
		status    int
		errCode   string
		aud       string
		scope     string
		issueCode bool
	}
	tests := []struct {
		name  string
		query string
		want  want
	}{
		{
			name:  "scope escalation is invalid_scope",
			query: "&scope=" + url.QueryEscape("openid admin"),
			want:  want{status: http.StatusBadRequest, errCode: "invalid_scope"},
		},
		{
			name:  "unregistered resource is invalid_target",
			query: "&scope=openid&resource=" + url.QueryEscape("https://evil.example.com"),
			want:  want{status: http.StatusBadRequest, errCode: "invalid_target"},
		},
		{
			name:  "two resources are invalid_target",
			query: "&scope=openid&resource=" + url.QueryEscape(resource) + "&resource=" + url.QueryEscape(resource+"/2"),
			want:  want{status: http.StatusBadRequest, errCode: "invalid_target"},
		},
		{
			name:  "registered resource reaches the token",
			query: "&scope=" + url.QueryEscape("openid profile") + "&resource=" + url.QueryEscape(resource),
			want:  want{status: http.StatusFound, issueCode: true, aud: resource, scope: "openid profile"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
			testApp.AllowedScopes = []string{"openid", "profile"}
			testApp.AllowedResources = []string{resource}
			testUser := &user.User{Username: "authorize-registry", Email: "authorize-registry@example.com", Name: "Authorize Registry"}
			sv := &fakeSessionValidator{}
			stack := buildHandlerTestStack(t, sv, testApp, testUser)
			sv.sess = &session.Session{ID: "sess-registry", UserID: testUser.ID}
			sv.u = testUser
			router := newTestRouter(stack.handler)

			reqURL := "/oauth/authorize?client_id=" + clientID +
				"&redirect_uri=" + url.QueryEscape(redirectURI) + "&response_type=code" + tc.query
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.AddCookie(&http.Cookie{Name: "passage_session", Value: "sess-token"})
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.want.status {
				t.Fatalf("authorize status = %d, want %d; body: %s", w.Code, tc.want.status, w.Body.String())
			}
			if !tc.want.issueCode {
				var body map[string]string
				if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
					t.Fatalf("decode error body: %v", err)
				}
				if body["error"] != tc.want.errCode {
					t.Errorf("error = %q, want %q", body["error"], tc.want.errCode)
				}
				return
			}

			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse redirect: %v", err)
			}
			code := loc.Query().Get("code")
			if code == "" {
				t.Fatalf("no code in redirect %q", loc.String())
			}

			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {redirectURI},
				"client_id":     {clientID},
				"client_secret": {plainSecret},
				"resource":      {resource},
			}
			req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("token status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			var resp oauth.TokenResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode token response: %v", err)
			}
			if resp.Scope != tc.want.scope {
				t.Errorf("scope = %q, want %q", resp.Scope, tc.want.scope)
			}
			if got := accessAudience(t, resp.AccessToken); got != tc.want.aud {
				t.Errorf("aud = %q, want %q", got, tc.want.aud)
			}
		})
	}
}
