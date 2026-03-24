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
	}
	for _, field := range requiredFields {
		if _, ok := doc[field]; !ok {
			t.Errorf("Discovery: missing field %q", field)
		}
	}

	if doc["issuer"] != "https://auth.example.com" {
		t.Errorf("Discovery issuer: got %v", doc["issuer"])
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
	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "state-1", testUser.ID)
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
	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	tokenResp, err := stack.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
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
	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	tokenResp, err := stack.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
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

	var info map[string]string
	if err := json.NewDecoder(w.Body).Decode(&info); err != nil {
		t.Fatalf("UserInfo valid: decode: %v", err)
	}
	if info["sub"] != testUser.ID {
		t.Errorf("UserInfo sub: got %q, want %q", info["sub"], testUser.ID)
	}
	if info["email"] != testUser.Email {
		t.Errorf("UserInfo email: got %q, want %q", info["email"], testUser.Email)
	}
	if info["preferred_username"] != testUser.Username {
		t.Errorf("UserInfo preferred_username: got %q, want %q", info["preferred_username"], testUser.Username)
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
	code, err := stack.svc.Authorize(ctx, clientID, redirectURI, "openid", "state-basic", testUser.ID)
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
