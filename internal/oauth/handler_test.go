package oauth_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// fakeSessionValidator is a simple in-memory session validator for handler tests.
type fakeSessionValidator struct {
	sess *session.Session
	u    *user.User
	err  error
}

func (f *fakeSessionValidator) ValidateSession(_ context.Context, _ string) (*session.Session, *user.User, error) {
	return f.sess, f.u, f.err
}

// handlerTestStack holds a Handler and the underlying Service and store DB.
type handlerTestStack struct {
	handler *oauth.Handler
	svc     *oauth.Service
	store   *oauth.SQLiteStore
	appID   string
	userID  string
}

// buildHandlerTestStack creates a real Service + Store + Handler for handler tests.
// It seeds real user and app rows in the DB to satisfy FK constraints.
func buildHandlerTestStack(t *testing.T, sv *fakeSessionValidator, testApp *app.App, testUser *user.User) *handlerTestStack {
	t.Helper()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	pemBytes, kid, err := store.GetOrCreateRSAKey(ctx)
	if err != nil {
		t.Fatalf("buildHandlerTestStack: GetOrCreateRSAKey: %v", err)
	}

	appID, userID := seedAppAndUserWithCredentials(t, db, testApp, testUser)
	testApp.ID = appID
	testUser.ID = userID

	apps := &fakeAppClient{app: testApp, access: true}
	users := &fakeUserReader{u: testUser}

	svc, err := oauth.NewService(store, apps, users, pemBytes, kid, "https://auth.example.com", slog.Default())
	if err != nil {
		t.Fatalf("buildHandlerTestStack: NewService: %v", err)
	}

	h := oauth.NewHandler(svc, sv, svc.PrivateKey().Public().(*rsa.PublicKey), svc.KeyID(), "https://auth.example.com", "passage_session", slog.Default())
	return &handlerTestStack{
		handler: h,
		svc:     svc,
		store:   store,
		appID:   appID,
		userID:  userID,
	}
}

// newTestRouter creates a chi Router with the handler's routes registered.
func newTestRouter(h *oauth.Handler) *chi.Mux {
	r := chi.NewRouter()
	h.Routes(r)
	return r
}

func TestHandler_Discovery(t *testing.T) {

	sv := &fakeSessionValidator{}
	testApp := buildTestApp(t, "client-1", "secret", []string{"https://example.com/cb"})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)

	r := newTestRouter(stack.handler)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Discovery: status %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Discovery: Content-Type %q, want application/json", ct)
	}

	var doc map[string]any
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("Discovery: decode JSON: %v", err)
	}

	requiredFields := []string{
		"issuer", "authorization_endpoint", "token_endpoint",
		"userinfo_endpoint", "jwks_uri", "response_types_supported",
		"subject_types_supported", "id_token_signing_alg_values_supported",
		"scopes_supported", "token_endpoint_auth_methods_supported",
		"grant_types_supported", "claims_supported",
		"code_challenge_methods_supported",
	}
	for _, field := range requiredFields {
		if _, ok := doc[field]; !ok {
			t.Errorf("Discovery: missing field %q", field)
		}
	}

	if doc["issuer"] != "https://auth.example.com" {
		t.Errorf("Discovery issuer: got %v", doc["issuer"])
	}

	// Verify code_challenge_methods_supported contains "S256" and "plain".
	methodsRaw, ok := doc["code_challenge_methods_supported"]
	if !ok {
		t.Fatal("Discovery: missing code_challenge_methods_supported")
	}
	methods, ok := methodsRaw.([]any)
	if !ok {
		t.Fatalf("Discovery: code_challenge_methods_supported is not an array, got %T", methodsRaw)
	}
	wantMethods := map[string]bool{"S256": false, "plain": false}
	for _, m := range methods {
		s, _ := m.(string)
		if _, known := wantMethods[s]; known {
			wantMethods[s] = true
		}
	}
	for method, found := range wantMethods {
		if !found {
			t.Errorf("Discovery: code_challenge_methods_supported missing %q", method)
		}
	}
}

func TestHandler_JWKS(t *testing.T) {

	sv := &fakeSessionValidator{}
	testApp := buildTestApp(t, "client-1", "secret", []string{"https://example.com/cb"})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)

	r := newTestRouter(stack.handler)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("JWKS: status %d, want 200", w.Code)
	}

	var jwks map[string]any
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("JWKS: decode JSON: %v", err)
	}

	keysRaw, ok := jwks["keys"]
	if !ok {
		t.Fatal("JWKS: missing keys field")
	}
	keys, ok := keysRaw.([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("JWKS: keys is not a non-empty array")
	}

	key, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatal("JWKS: first key is not an object")
	}
	if key["kty"] != "RSA" {
		t.Errorf("JWKS key kty: got %v, want RSA", key["kty"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("JWKS key alg: got %v, want RS256", key["alg"])
	}
	if _, ok := key["n"]; !ok {
		t.Error("JWKS key: missing n (modulus)")
	}
	if _, ok := key["e"]; !ok {
		t.Error("JWKS key: missing e (exponent)")
	}
	if key["use"] != "sig" {
		t.Errorf("JWKS key use: got %v, want sig", key["use"])
	}
	kid, ok := key["kid"].(string)
	if !ok || kid == "" {
		t.Errorf("JWKS key kid: got %v, want non-empty string", key["kid"])
	}
}

func TestHandler_Authorize_RedirectsToLogin(t *testing.T) {

	// No valid session.
	sv := &fakeSessionValidator{err: session.ErrSessionNotFound}
	testApp := buildTestApp(t, "client-1", "secret", []string{"https://example.com/cb"})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)

	r := newTestRouter(stack.handler)

	reqURL := "/oauth/authorize?client_id=client-1&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&response_type=code&scope=openid"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	// No session cookie.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("Authorize no session: status %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/auth/start") {
		t.Errorf("Authorize no session: redirect location %q should contain /auth/start", loc)
	}
	if !strings.Contains(loc, "rd=") {
		t.Errorf("Authorize no session: redirect location %q should contain rd= param", loc)
	}
}

func TestHandler_Authorize_Success(t *testing.T) {
	const (
		clientID    = "client-success"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}

	sv := &fakeSessionValidator{
		sess: &session.Session{ID: "sess-1"},
		// u will be set after seeding
	}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	// Update session validator's user to use the seeded user ID.
	sv.u = testUser
	sv.sess.UserID = testUser.ID

	r := newTestRouter(stack.handler)

	reqURL := fmt.Sprintf(
		"/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid&state=xyz",
		clientID,
		url.QueryEscape(redirectURI),
	)
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.AddCookie(&http.Cookie{Name: "passage_session", Value: "sess-token-1"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("Authorize success: status %d, want 302; body: %s", w.Code, w.Body.String())
	}

	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Authorize success: parse redirect: %v", err)
	}
	if parsed.Query().Get("code") == "" {
		t.Errorf("Authorize success: redirect %q missing code param", loc)
	}
	if parsed.Query().Get("state") != "xyz" {
		t.Errorf("Authorize success: redirect %q missing state param", loc)
	}
}

func TestHandler_Token_AuthCode(t *testing.T) {
	const (
		clientID    = "client-token"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "bob", Email: "bob@example.com", Name: "Bob"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	sv.sess = &session.Session{ID: "sess-2", UserID: testUser.ID}
	sv.u = testUser

	r := newTestRouter(stack.handler)

	// Get a code via the service.
	ctx := context.Background()
	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "state-1", "", "", "", time.Now(), testUser.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// Exchange code for tokens via HTTP.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Token AuthCode: status %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var resp oauth.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Token AuthCode: decode response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("Token AuthCode: empty access_token")
	}
	if resp.IDToken == "" {
		t.Error("Token AuthCode: empty id_token")
	}
	if resp.RefreshToken == "" {
		t.Error("Token AuthCode: empty refresh_token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Token AuthCode token_type: got %q, want Bearer", resp.TokenType)
	}
}

func TestHandler_Token_Refresh(t *testing.T) {
	const (
		clientID    = "client-refresh"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "carol", Email: "carol@example.com", Name: "Carol"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	sv.u = testUser

	r := newTestRouter(stack.handler)

	// Get initial tokens.
	ctx := context.Background()
	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "", "", "", "", time.Now(), testUser.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	tokenResp, err := stack.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	// Refresh tokens via HTTP.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenResp.RefreshToken},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Token Refresh: status %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var refreshed oauth.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&refreshed); err != nil {
		t.Fatalf("Token Refresh: decode: %v", err)
	}
	if refreshed.RefreshToken == tokenResp.RefreshToken {
		t.Error("Token Refresh: refresh token was not rotated")
	}

	// Second use of the old refresh token should fail.
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenResp.RefreshToken},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("Token Refresh second use: status %d, want 400", w2.Code)
	}

	var errResp map[string]string
	if err := json.NewDecoder(w2.Body).Decode(&errResp); err != nil {
		t.Fatalf("Token Refresh second use: decode error: %v", err)
	}
	if errResp["error"] != "invalid_grant" {
		t.Errorf("Token Refresh second use: error %q, want invalid_grant", errResp["error"])
	}
}

func TestHandler_UserInfo_Valid(t *testing.T) {
	const (
		clientID    = "client-userinfo"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "dave", Email: "dave@example.com", Name: "Dave"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)

	r := newTestRouter(stack.handler)

	// Get an access token.
	ctx := context.Background()
	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "", "", "", "", time.Now(), testUser.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	tokenResp, err := stack.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("UserInfo valid: status %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var info map[string]any
	if err := json.NewDecoder(w.Body).Decode(&info); err != nil {
		t.Fatalf("UserInfo valid: decode: %v", err)
	}
	if sub, _ := info["sub"].(string); sub != testUser.ID {
		t.Errorf("UserInfo sub: got %q, want %q", sub, testUser.ID)
	}
	if email, _ := info["email"].(string); email != testUser.Email {
		t.Errorf("UserInfo email: got %q, want %q", email, testUser.Email)
	}
	if username, _ := info["preferred_username"].(string); username != testUser.Username {
		t.Errorf("UserInfo preferred_username: got %q, want %q", username, testUser.Username)
	}
	// email_verified must be the JSON boolean true — Grist and other OIDC
	// clients use a strict === true check; a string "true" is not sufficient.
	emailVerified, ok := info["email_verified"].(bool)
	if !ok {
		t.Errorf("UserInfo email_verified: expected bool, got %T", info["email_verified"])
	} else if !emailVerified {
		t.Errorf("UserInfo email_verified: got false, want true")
	}
}

func TestHandler_UserInfo_NoToken(t *testing.T) {
	sv := &fakeSessionValidator{}
	testApp := buildTestApp(t, "client-1", "secret", []string{"https://example.com/cb"})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	r := newTestRouter(stack.handler)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	// No Authorization header.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("UserInfo no token: status %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("UserInfo no token: missing WWW-Authenticate header")
	}
}

func TestHandler_UserInfo_ExpiredToken(t *testing.T) {
	const (
		clientID    = "client-expired"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "eve", Email: "eve@example.com", Name: "Eve"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	r := newTestRouter(stack.handler)

	// Insert an expired access token directly.
	ctx := context.Background()
	expiredToken := &oauth.Token{
		AppID:     stack.appID,
		UserID:    stack.userID,
		Scopes:    "openid",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	if err := stack.store.CreateToken(ctx, expiredToken); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken.Token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("UserInfo expired token: status %d, want 401", w.Code)
	}
}

// TestHandler_Token_BasicAuth verifies that client credentials supplied via
// HTTP Basic auth (RFC 6749 §2.3.1) work identically to form-body credentials.
func TestHandler_Token_BasicAuth(t *testing.T) {
	const (
		clientID    = "client-basic-auth"
		plainSecret = "test-secret-basic"
		redirectURI = "https://example.com/callback"
	)

	hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "frank", Email: "frank@example.com", Name: "Frank"}
	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	sv.sess = &session.Session{ID: "sess-basic", UserID: testUser.ID}
	sv.u = testUser

	r := newTestRouter(stack.handler)

	// Obtain a code via the service directly.
	ctx := context.Background()
	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "state-basic", "", "", "", time.Now(), testUser.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// Exchange the code using HTTP Basic auth for client credentials (no form body client_id/secret).
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {redirectURI},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, plainSecret)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Token BasicAuth: status %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var resp oauth.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Token BasicAuth: decode response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("Token BasicAuth: empty access_token")
	}
	if resp.IDToken == "" {
		t.Error("Token BasicAuth: empty id_token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Token BasicAuth token_type: got %q, want Bearer", resp.TokenType)
	}
}

// TestHandler_AuthCodeFlow_EndToEnd exercises the full OAuth2 authorization
// code flow in sequence: authorize → token exchange → userinfo → refresh →
// replay of consumed refresh token.
func TestHandler_AuthCodeFlow_EndToEnd(t *testing.T) {
	const (
		clientID    = "client-e2e"
		plainSecret = "e2e-secret"
		redirectURI = "https://example.com/e2e-callback"
	)

	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "e2euser", Email: "e2e@example.com", Name: "E2E User"}

	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	sv.sess = &session.Session{ID: "sess-e2e", UserID: testUser.ID}
	sv.u = testUser

	r := newTestRouter(stack.handler)

	// ── Step 1: GET /oauth/authorize with valid session → expect 302 + code ──
	reqURL := fmt.Sprintf(
		"/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=test-state",
		clientID,
		url.QueryEscape(redirectURI),
		url.QueryEscape("openid profile email"),
	)
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.AddCookie(&http.Cookie{Name: "passage_session", Value: "sess-token-e2e"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status %d, want 302; body: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("authorize: parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize: no code in redirect location %q", loc)
	}
	if parsed.Query().Get("state") != "test-state" {
		t.Errorf("authorize: state %q, want test-state", parsed.Query().Get("state"))
	}

	// ── Step 2: POST /oauth/token (authorization_code) → expect 200 + tokens ──
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
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("token exchange: status %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var tokenResp oauth.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("token exchange: decode: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Error("token exchange: empty access_token")
	}
	if tokenResp.IDToken == "" {
		t.Error("token exchange: empty id_token")
	}
	if tokenResp.RefreshToken == "" {
		t.Error("token exchange: empty refresh_token")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("token exchange: token_type %q, want Bearer", tokenResp.TokenType)
	}
	if tokenResp.ExpiresIn <= 0 {
		t.Errorf("token exchange: expires_in %d, want > 0", tokenResp.ExpiresIn)
	}

	// ── Step 3: GET /oauth/userinfo with Bearer token → expect 200 + sub/email ──
	req = httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("userinfo: status %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var userInfo map[string]any
	if err := json.NewDecoder(w.Body).Decode(&userInfo); err != nil {
		t.Fatalf("userinfo: decode: %v", err)
	}
	sub, _ := userInfo["sub"].(string)
	if sub != testUser.ID {
		t.Errorf("userinfo sub: got %q, want %q", sub, testUser.ID)
	}
	if email, _ := userInfo["email"].(string); email == "" {
		t.Error("userinfo: empty email")
	}

	// ── Step 4: POST /oauth/token (refresh_token) → expect 200 + NEW tokens ──
	oldRefreshToken := tokenResp.RefreshToken
	form = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRefreshToken},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("refresh: status %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var refreshResp oauth.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&refreshResp); err != nil {
		t.Fatalf("refresh: decode: %v", err)
	}
	if refreshResp.AccessToken == tokenResp.AccessToken {
		t.Error("refresh: access_token was not rotated")
	}
	if refreshResp.RefreshToken == oldRefreshToken {
		t.Error("refresh: refresh_token was not rotated")
	}
	if refreshResp.RefreshToken == "" {
		t.Error("refresh: new refresh_token is empty")
	}
	if refreshResp.AccessToken == "" {
		t.Error("refresh: new access_token is empty")
	}

	// ── Step 5: Replay old refresh token → expect 400 + invalid_grant ──
	form = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRefreshToken},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("replay refresh: status %d, want 400", w.Code)
	}
	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("replay refresh: decode error: %v", err)
	}
	if errResp["error"] != "invalid_grant" {
		t.Errorf("replay refresh: error %q, want invalid_grant", errResp["error"])
	}
}

// TestHandler_Token_InvalidRequests verifies that malformed token requests
// return HTTP 400 with a non-empty JSON error field.
func TestHandler_Token_InvalidRequests(t *testing.T) {
	sv := &fakeSessionValidator{}
	testApp := buildTestApp(t, "client-invalid", "secret", []string{"https://example.com/cb"})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	r := newTestRouter(stack.handler)

	// validOAuthErrorCodes is the set of RFC 6749 error codes we accept.
	validOAuthErrorCodes := map[string]bool{
		"invalid_request":        true,
		"invalid_client":         true,
		"invalid_grant":          true,
		"unauthorized_client":    true,
		"unsupported_grant_type": true,
		"invalid_scope":          true,
	}

	tests := []struct {
		name string
		body url.Values
	}{
		{
			name: "missing grant_type",
			body: url.Values{"client_id": {"x"}, "client_secret": {"y"}},
		},
		{
			name: "unknown grant_type",
			body: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"x"},
				"client_secret": {"y"},
			},
		},
		{
			name: "missing code for auth_code grant",
			body: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"x"},
				"client_secret": {"y"},
				"redirect_uri":  {"http://x"},
			},
		},
		{
			name: "missing refresh_token for refresh grant",
			body: url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {"x"},
				"client_secret": {"y"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tc.body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: status %d, want 400; body: %s", tc.name, w.Code, w.Body.String())
			}

			var errBody map[string]string
			if err := json.NewDecoder(w.Body).Decode(&errBody); err != nil {
				t.Fatalf("%s: decode error body: %v", tc.name, err)
			}
			errCode := errBody["error"]
			if errCode == "" {
				t.Errorf("%s: error field is empty in response", tc.name)
			} else if !validOAuthErrorCodes[errCode] {
				t.Errorf("%s: error %q is not a valid RFC 6749 error code", tc.name, errCode)
			}
		})
	}
}

// TestHandler_Authorize_PKCE_BadChallenge verifies that sending an unsupported
// code_challenge_method to the authorize endpoint returns 400 invalid_request.
func TestHandler_Authorize_PKCE_BadChallenge(t *testing.T) {
	const (
		clientID    = "client-pkce-badmethod"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "pkce-bad", Email: "pkce-bad@example.com", Name: "PKCE Bad"}
	sv := &fakeSessionValidator{
		sess: &session.Session{ID: "sess-pkce-bad"},
	}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	sv.u = testUser
	sv.sess.UserID = testUser.ID

	r := newTestRouter(stack.handler)

	// Use a valid-length challenge (43 chars) but an unsupported method.
	challenge := makeS256Challenge(t, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	reqURL := fmt.Sprintf(
		"/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid&code_challenge=%s&code_challenge_method=bad_method_xyz",
		clientID,
		url.QueryEscape(redirectURI),
		url.QueryEscape(challenge),
	)
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.AddCookie(&http.Cookie{Name: "passage_session", Value: "sess-token-pkce-bad"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Authorize PKCE bad method: status %d, want 400; body: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Authorize PKCE bad method: decode error body: %v", err)
	}
	if errResp["error"] != "invalid_request" {
		t.Errorf("Authorize PKCE bad method: error %q, want invalid_request", errResp["error"])
	}
}

// TestHandler_Token_PKCE exercises the token endpoint PKCE scenarios
// via the full authorize → token exchange flow at the HTTP handler level.
func TestHandler_Token_PKCE(t *testing.T) {
	const (
		clientID    = "client-pkce-token"
		plainSecret = "pkce-token-secret"
		redirectURI = "https://example.com/pkce-callback"
		// verifier is 43 unreserved ASCII chars — valid per RFC 7636 §4.1.
		verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	)

	s256Challenge := makeS256Challenge(t, verifier)

	tests := []struct {
		name          string
		challenge     string
		method        string
		tokenVerifier string
		wantStatus    int
		wantError     string // empty means success
	}{
		{
			name:          "s256_success",
			challenge:     s256Challenge,
			method:        "S256",
			tokenVerifier: verifier,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "s256_wrong_verifier",
			challenge:     s256Challenge,
			method:        "S256",
			tokenVerifier: "wrong-verifier-that-is-definitely-43-chars-long",
			wantStatus:    http.StatusBadRequest,
			wantError:     "invalid_grant",
		},
		{
			name:          "no_pkce_backward_compat",
			challenge:     "",
			method:        "",
			tokenVerifier: "",
			wantStatus:    http.StatusOK,
		},
		{
			name:          "no_pkce_spurious_verifier",
			challenge:     "",
			method:        "",
			tokenVerifier: verifier,
			wantStatus:    http.StatusBadRequest,
			wantError:     "invalid_grant",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
			testApp := &app.App{
				ClientID:         clientID,
				ClientSecretHash: string(hash),
				RedirectURIs:     []string{redirectURI},
				OAuthEnabled:     true,
			}
			testUser := &user.User{Username: "pkce-token-user", Email: "pkcetoken@example.com", Name: "PKCE Token User"}
			sv := &fakeSessionValidator{
				sess: &session.Session{ID: "sess-pkce-token"},
			}
			stack := buildHandlerTestStack(t, sv, testApp, testUser)
			sv.u = testUser
			sv.sess.UserID = testUser.ID

			r := newTestRouter(stack.handler)

			// ── Step 1: GET /oauth/authorize with PKCE params ──
			authURL := fmt.Sprintf(
				"/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid",
				clientID,
				url.QueryEscape(redirectURI),
			)
			if tc.challenge != "" {
				authURL += "&code_challenge=" + url.QueryEscape(tc.challenge)
				if tc.method != "" {
					authURL += "&code_challenge_method=" + tc.method
				}
			}

			req := httptest.NewRequest(http.MethodGet, authURL, nil)
			req.AddCookie(&http.Cookie{Name: "passage_session", Value: "sess-pkce-token-val"})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusFound {
				t.Fatalf("authorize: status %d, want 302; body: %s", w.Code, w.Body.String())
			}
			loc := w.Header().Get("Location")
			parsed, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("authorize: parse redirect: %v", err)
			}
			code := parsed.Query().Get("code")
			if code == "" {
				t.Fatalf("authorize: no code in redirect %q", loc)
			}

			// ── Step 2: POST /oauth/token with optional code_verifier ──
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {redirectURI},
				"client_id":     {clientID},
				"client_secret": {plainSecret},
			}
			if tc.tokenVerifier != "" {
				form.Set("code_verifier", tc.tokenVerifier)
			}

			req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w = httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("token exchange: status %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}

			if tc.wantError != "" {
				var errResp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
					t.Fatalf("token exchange: decode error body: %v", err)
				}
				if errResp["error"] != tc.wantError {
					t.Errorf("token exchange: error %q, want %q", errResp["error"], tc.wantError)
				}
			} else {
				var resp oauth.TokenResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("token exchange: decode response: %v", err)
				}
				if resp.AccessToken == "" {
					t.Error("token exchange: empty access_token")
				}
			}
		})
	}
}

// TestHandler_AuthCodeFlow_EndToEnd_PKCE exercises the full OAuth2 authorization
// code flow with S256 PKCE through every HTTP handler layer:
// authorize (with challenge) → token exchange (with verifier) → userinfo.
func TestHandler_AuthCodeFlow_EndToEnd_PKCE(t *testing.T) {
	const (
		clientID    = "client-e2e-pkce"
		plainSecret = "e2e-pkce-secret"
		redirectURI = "https://example.com/e2e-pkce-callback"
		// verifier is 43 unreserved ASCII chars — valid per RFC 7636 §4.1.
		verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	)

	challenge := makeS256Challenge(t, verifier)

	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	testApp := &app.App{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     []string{redirectURI},
		OAuthEnabled:     true,
	}
	testUser := &user.User{Username: "e2epkceuser", Email: "e2epkce@example.com", Name: "E2E PKCE User"}

	sv := &fakeSessionValidator{}
	stack := buildHandlerTestStack(t, sv, testApp, testUser)
	sv.sess = &session.Session{ID: "sess-e2e-pkce", UserID: testUser.ID}
	sv.u = testUser

	r := newTestRouter(stack.handler)

	// ── Step 1: GET /oauth/authorize with S256 PKCE challenge → expect 302 + code ──
	reqURL := fmt.Sprintf(
		"/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=pkce-state&code_challenge=%s&code_challenge_method=S256",
		clientID,
		url.QueryEscape(redirectURI),
		url.QueryEscape("openid profile email"),
		url.QueryEscape(challenge),
	)
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.AddCookie(&http.Cookie{Name: "passage_session", Value: "sess-token-e2e-pkce"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status %d, want 302; body: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("authorize: parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize: no code in redirect location %q", loc)
	}
	if parsed.Query().Get("state") != "pkce-state" {
		t.Errorf("authorize: state %q, want pkce-state", parsed.Query().Get("state"))
	}

	// ── Step 2: POST /oauth/token with correct code_verifier → expect 200 + tokens ──
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {plainSecret},
		"code_verifier": {verifier},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("token exchange: status %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var tokenResp oauth.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("token exchange: decode: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Error("token exchange: empty access_token")
	}
	if tokenResp.IDToken == "" {
		t.Error("token exchange: empty id_token")
	}
	if tokenResp.RefreshToken == "" {
		t.Error("token exchange: empty refresh_token")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("token exchange: token_type %q, want Bearer", tokenResp.TokenType)
	}

	// ── Step 3: GET /oauth/userinfo with Bearer token → expect 200 ──
	req = httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("userinfo: status %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var userInfo map[string]any
	if err := json.NewDecoder(w.Body).Decode(&userInfo); err != nil {
		t.Fatalf("userinfo: decode: %v", err)
	}
	sub, _ := userInfo["sub"].(string)
	if sub != testUser.ID {
		t.Errorf("userinfo sub: got %q, want %q", sub, testUser.ID)
	}
}

// TestHandler_Authorize_ErrorRouting verifies that the /oauth/authorize endpoint
// returns the correct RFC 6749 error code and description for each distinct
// failure mode. Previously, ErrOAuthNotEnabled and ErrRedirectURIMismatch were
// both incorrectly mapped to the PKCE error message "invalid code_challenge or
// code_challenge_method", which masked the true cause of failures for non-PKCE
// clients.
func TestHandler_Authorize_ErrorRouting(t *testing.T) {
	const (
		clientID    = "client-error-routing"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	tests := []struct {
		name            string
		oauthEnabled    bool
		requestClientID string
		requestRedirect string
		// code_challenge is intentionally empty for all cases — this tests
		// that non-PKCE requests are diagnosed correctly.
		wantStatus int
		wantError  string
		wantDesc   string
	}{
		{
			name:            "oauth_not_enabled_returns_unauthorized_client",
			oauthEnabled:    false,
			requestClientID: clientID,
			requestRedirect: redirectURI,
			wantStatus:      http.StatusBadRequest,
			wantError:       "unauthorized_client",
			wantDesc:        "OAuth is not enabled for this client",
		},
		{
			name:            "redirect_uri_mismatch_returns_specific_message",
			oauthEnabled:    true,
			requestClientID: clientID,
			requestRedirect: "https://evil.example.com/callback",
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_request",
			wantDesc:        "redirect_uri does not match registered URIs",
		},
		{
			// Regression: neither of the above should ever return the PKCE
			// error message when no code_challenge was sent.
			name:            "redirect_uri_mismatch_does_not_mention_pkce",
			oauthEnabled:    true,
			requestClientID: clientID,
			requestRedirect: "https://evil.example.com/callback",
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_request",
			wantDesc:        "redirect_uri does not match registered URIs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, _ := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
			testApp := &app.App{
				ClientID:         clientID,
				ClientSecretHash: string(hash),
				RedirectURIs:     []string{redirectURI},
				OAuthEnabled:     tc.oauthEnabled,
			}
			testUser := &user.User{Username: "frank", Email: "frank@example.com", Name: "Frank"}

			sv := &fakeSessionValidator{}
			stack := buildHandlerTestStack(t, sv, testApp, testUser)
			sv.sess = &session.Session{ID: "sess-routing", UserID: testUser.ID}
			sv.u = testUser

			r := newTestRouter(stack.handler)

			reqURL := fmt.Sprintf(
				"/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid",
				tc.requestClientID,
				url.QueryEscape(tc.requestRedirect),
			)
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.AddCookie(&http.Cookie{Name: "passage_session", Value: "sess-token"})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}

			var body map[string]string
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("decode response body: %v", err)
			}
			if body["error"] != tc.wantError {
				t.Errorf("error: got %q, want %q", body["error"], tc.wantError)
			}
			if body["error_description"] != tc.wantDesc {
				t.Errorf("error_description: got %q, want %q", body["error_description"], tc.wantDesc)
			}
			// Regression guard: none of these cases should blame PKCE.
			if body["error_description"] == "invalid code_challenge or code_challenge_method" {
				t.Errorf("error_description incorrectly mentions PKCE for a non-PKCE request")
			}
		})
	}
}
