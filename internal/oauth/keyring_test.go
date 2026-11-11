package oauth_test

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

const (
	keyTestClientID     = "key-test-client"
	keyTestClientSecret = "key-test-secret"
	keyTestRedirectURI  = "https://example.com/callback"
)

// TestService_SigningKeyRotation covers the whole kid-history lifecycle:
// rotation changes the signing kid, the old key keeps verifying, retirement
// stops it verifying, and deletion removes it.
func TestService_SigningKeyRotation(t *testing.T) {
	ctx := context.Background()

	testApp := buildTestApp(t, keyTestClientID, keyTestClientSecret, []string{keyTestRedirectURI})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	sc := newTestServiceWithDB(t, testutil.NewTestDB(t), testApp, testUser)

	active := sc.svc.ActiveSigningKeys()
	if len(active) != 1 {
		t.Fatalf("initial active keys = %d, want 1", len(active))
	}
	firstKID := active[0].KID

	firstToken := issueKeyTestIDToken(t, sc)
	if got := idTokenKID(t, firstToken); got != firstKID {
		t.Fatalf("first id_token kid = %q, want %q", got, firstKID)
	}

	// ── Rotate: a new key signs, the old one stays active. ────────────────
	rotated, err := sc.svc.RotateSigningKey(ctx)
	if err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}
	if rotated.KID == firstKID {
		t.Fatal("rotation reused the existing kid")
	}
	if rotated.CreatedAt.IsZero() {
		t.Error("rotated key has a zero created_at")
	}

	active = sc.svc.ActiveSigningKeys()
	if len(active) != 2 {
		t.Fatalf("active keys after rotation = %d, want 2", len(active))
	}
	if active[0].KID != rotated.KID {
		t.Errorf("current key = %q, want the rotated key %q", active[0].KID, rotated.KID)
	}

	secondToken := issueKeyTestIDToken(t, sc)
	if got := idTokenKID(t, secondToken); got != rotated.KID {
		t.Fatalf("id_token after rotation uses kid %q, want %q", got, rotated.KID)
	}

	// The old token still verifies, both through the logout-hint path and
	// against the JWKS the way a relying party would check it.
	if _, err := sc.svc.ClientForIDTokenHint(ctx, firstToken); err != nil {
		t.Fatalf("id_token signed by the previous key no longer verifies: %v", err)
	}
	jwks := fetchKeyTestJWKS(t, sc.svc)
	if _, ok := jwks[firstKID]; !ok {
		t.Error("JWKS after rotation does not serve the previous key")
	}
	if _, ok := jwks[rotated.KID]; !ok {
		t.Error("JWKS after rotation does not serve the new key")
	}
	assertSignedByKID(t, firstToken, jwks, firstKID)
	assertSignedByKID(t, secondToken, jwks, rotated.KID)

	// ── Retire: the key leaves the JWKS and is no longer accepted. ────────
	if err := sc.svc.RetireSigningKey(ctx, firstKID); err != nil {
		t.Fatalf("RetireSigningKey: %v", err)
	}
	if _, err := sc.svc.ClientForIDTokenHint(ctx, firstToken); !errors.Is(err, oauth.ErrInvalidIDTokenHint) {
		t.Errorf("retired key still verifies a hint: got %v, want ErrInvalidIDTokenHint", err)
	}
	if _, err := sc.svc.ClientForIDTokenHint(ctx, secondToken); err != nil {
		t.Fatalf("current key stopped verifying after retiring the old key: %v", err)
	}
	jwks = fetchKeyTestJWKS(t, sc.svc)
	if _, ok := jwks[firstKID]; ok {
		t.Error("retired key is still served in the JWKS")
	}
	if _, ok := jwks[rotated.KID]; !ok {
		t.Error("current key is missing from the JWKS")
	}

	// ── Delete: only the retired key can go, and it is gone for good. ─────
	if err := sc.svc.DeleteSigningKey(ctx, rotated.KID); !errors.Is(err, oauth.ErrSigningKeyActive) {
		t.Errorf("DeleteSigningKey(active) = %v, want ErrSigningKeyActive", err)
	}
	if err := sc.svc.DeleteSigningKey(ctx, firstKID); err != nil {
		t.Fatalf("DeleteSigningKey(retired): %v", err)
	}
	keys, err := sc.svc.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].KID != rotated.KID {
		t.Fatalf("keys after delete = %d, want only the current key", len(keys))
	}
	if err := sc.svc.DeleteSigningKey(ctx, firstKID); !errors.Is(err, oauth.ErrSigningKeyNotFound) {
		t.Errorf("DeleteSigningKey(unknown) = %v, want ErrSigningKeyNotFound", err)
	}
}

// TestService_SigningKeyRetireLastRefused proves the issuer can never lose its
// only signing key.
func TestService_SigningKeyRetireLastRefused(t *testing.T) {
	ctx := context.Background()
	testApp := buildTestApp(t, keyTestClientID, keyTestClientSecret, []string{keyTestRedirectURI})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	sc := newTestServiceWithDB(t, testutil.NewTestDB(t), testApp, testUser)

	only := sc.svc.ActiveSigningKeys()[0].KID
	if err := sc.svc.RetireSigningKey(ctx, only); !errors.Is(err, oauth.ErrSigningKeyLast) {
		t.Fatalf("retiring the only key = %v, want ErrSigningKeyLast", err)
	}
	if got := sc.svc.ActiveSigningKeys(); len(got) != 1 || got[0].KID != only {
		t.Fatal("the only key was retired despite the refusal")
	}
	if err := sc.svc.RetireSigningKey(ctx, "does-not-exist"); !errors.Is(err, oauth.ErrSigningKeyNotFound) {
		t.Errorf("retiring an unknown kid = %v, want ErrSigningKeyNotFound", err)
	}

	// Retiring is idempotent once another key exists.
	if _, err := sc.svc.RotateSigningKey(ctx); err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}
	if err := sc.svc.RetireSigningKey(ctx, only); err != nil {
		t.Fatalf("RetireSigningKey: %v", err)
	}
	if err := sc.svc.RetireSigningKey(ctx, only); err != nil {
		t.Fatalf("RetireSigningKey second call: %v", err)
	}
}

// TestService_SigningKeyRingSurvivesRestart proves the keyring is rebuilt from
// the database, with the newest key current.
func TestService_SigningKeyRingSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	database := testutil.NewTestDB(t)
	testApp := buildTestApp(t, keyTestClientID, keyTestClientSecret, []string{keyTestRedirectURI})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}

	sc := newTestServiceWithDB(t, database, testApp, testUser)
	firstKID := sc.svc.ActiveSigningKeys()[0].KID
	rotated, err := sc.svc.RotateSigningKey(ctx)
	if err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}

	// A new Service over the same store models a process restart.
	apps := &fakeAppClient{app: testApp, access: true}
	users := &fakeUserReader{u: testUser}
	restarted, err := oauth.NewService(ctx, oauth.NewStore(database), apps, users, "https://auth.example.com", discardLogger())
	if err != nil {
		t.Fatalf("NewService after restart: %v", err)
	}

	active := restarted.ActiveSigningKeys()
	if len(active) != 2 {
		t.Fatalf("active keys after restart = %d, want 2", len(active))
	}
	if active[0].KID != rotated.KID {
		t.Errorf("current key after restart = %q, want %q", active[0].KID, rotated.KID)
	}
	if active[1].KID != firstKID {
		t.Errorf("second key after restart = %q, want %q", active[1].KID, firstKID)
	}
}

// TestHandler_JWKS_ServesEveryActiveKey checks the endpoint shape with kid
// history: one entry per active key, each with its own kid.
func TestHandler_JWKS_ServesEveryActiveKey(t *testing.T) {
	ctx := context.Background()
	testApp := buildTestApp(t, keyTestClientID, keyTestClientSecret, []string{keyTestRedirectURI})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	stack := buildHandlerTestStack(t, &fakeSessionValidator{}, testApp, testUser)

	first := stack.svc.ActiveSigningKeys()[0].KID
	rotated, err := stack.svc.RotateSigningKey(ctx)
	if err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}

	r := newTestRouter(stack.handler)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("JWKS: status %d, want 200", w.Code)
	}

	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("JWKS: decode: %v", err)
	}
	if len(body.Keys) != 2 {
		t.Fatalf("JWKS keys = %d, want 2", len(body.Keys))
	}
	kids := map[string]bool{}
	for _, key := range body.Keys {
		kid, _ := key["kid"].(string)
		kids[kid] = true
	}
	if !kids[first] || !kids[rotated.KID] {
		t.Errorf("JWKS kids = %v, want both %q and %q", kids, first, rotated.KID)
	}
}

// issueKeyTestIDToken runs authorize + exchange and returns the id_token.
func issueKeyTestIDToken(t *testing.T, sc *testServiceContext) string {
	t.Helper()
	ctx := context.Background()
	code, err := sc.svc.Authorize(ctx, keyTestClientID, keyTestRedirectURI, "openid", "", "", "", "", time.Now(), sc.userID, "127.0.0.1")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	resp, err := sc.svc.ExchangeCode(ctx, code.Code, keyTestClientID, keyTestClientSecret, keyTestRedirectURI, "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.IDToken == "" {
		t.Fatal("ExchangeCode: empty id_token")
	}
	return resp.IDToken
}

// idTokenKID reads the kid from a token header without verifying it.
func idTokenKID(t *testing.T, token string) string {
	t.Helper()
	parsed, _, err := jwtlib.NewParser().ParseUnverified(token, jwtlib.MapClaims{})
	if err != nil {
		t.Fatalf("parse id_token header: %v", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	return kid
}

// fetchKeyTestJWKS calls the JWKS endpoint through the real handler and
// decodes each RSA public key by kid.
func fetchKeyTestJWKS(t *testing.T, svc *oauth.Service) map[string]*rsa.PublicKey {
	t.Helper()
	// The handler is the only producer of the JSON; build a minimal one so the
	// test exercises the same encoding path as production.
	h := oauth.NewHandler(svc, &fakeSessionValidator{}, "https://auth.example.com", nil, testConfig(), discardLogger())
	r := newTestRouter(h)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("JWKS: status %d, want 200", w.Code)
	}

	var body struct {
		Keys []struct {
			KID string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("JWKS: decode: %v", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(body.Keys))
	for _, key := range body.Keys {
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			t.Fatalf("JWKS: decode modulus: %v", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			t.Fatalf("JWKS: decode exponent: %v", err)
		}
		e := new(big.Int).SetBytes(eBytes)
		keys[key.KID] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}
	}
	return keys
}

// assertSignedByKID verifies token with the public key named by kid, exactly as
// a relying party would after reading the JWKS.
func assertSignedByKID(t *testing.T, token string, keys map[string]*rsa.PublicKey, kid string) {
	t.Helper()
	pub, ok := keys[kid]
	if !ok {
		t.Fatalf("JWKS has no key for kid %q", kid)
	}
	if _, err := jwtlib.Parse(token, func(*jwtlib.Token) (any, error) { return pub, nil },
		jwtlib.WithValidMethods([]string{"RS256"})); err != nil {
		t.Errorf("token signed by kid %q does not verify against the JWKS: %v", kid, err)
	}
}

// discardLogger returns a logger that drops every record.
func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
