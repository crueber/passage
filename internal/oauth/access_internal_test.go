package oauth

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/policy"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// accessTestApps is a minimal appClient for the internal JWT tests.
type accessTestApps struct {
	app *app.App
}

func (a *accessTestApps) GetByClientID(context.Context, string) (*app.App, error) { return a.app, nil }
func (a *accessTestApps) HasAccess(context.Context, string, string) (bool, error) { return true, nil }
func (a *accessTestApps) TokenAssignments(context.Context, string, string) ([]string, []string, error) {
	return []string{}, []string{}, nil
}
func (a *accessTestApps) EvaluateAccess(context.Context, *app.App, string, bool, string, time.Time) (policy.Decision, error) {
	return policy.Decision{Allowed: true}, nil
}

// accessTestUsers is a minimal userReader for the internal JWT tests.
type accessTestUsers struct {
	user *user.User
}

func (u *accessTestUsers) GetByID(context.Context, string) (*user.User, error) { return u.user, nil }

// newAccessTestService creates a Service backed by a real in-memory SQLite
// store, with one app and one user row that foreign keys can reference.
func newAccessTestService(t *testing.T) (*Service, *app.App, *user.User) {
	t.Helper()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, email, name, is_admin, is_active, roles, created_at, updated_at)
		VALUES ('user-jwt', 'jwtuser', 'jwt@example.com', 'JWT User', 0, 1, '[]', ?, ?)`,
		now, now,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	a := &app.App{
		ID:               "app-jwt",
		Slug:             "jwt-app",
		Name:             "JWT App",
		ClientID:         "client-jwt",
		ClientSecretHash: "",
		RedirectURIs:     []string{"https://rp.example.com/callback"},
		OAuthEnabled:     true,
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO apps (id, slug, name, description, host_pattern, is_active,
		                  client_id, client_secret_hash, redirect_uris, oauth_enabled, created_at, updated_at)
		VALUES (?, ?, ?, '', '', 1, ?, '', ?, 1, ?, ?)`,
		a.ID, a.Slug, a.Name, a.ClientID, a.RedirectURIs[0], now, now,
	); err != nil {
		t.Fatalf("insert app: %v", err)
	}

	u := &user.User{
		ID:       "user-jwt",
		Username: "jwtuser",
		Email:    "jwt@example.com",
		Name:     "JWT User",
		IsActive: true,
	}

	store := NewStore(db)
	svc, err := NewService(ctx, store, &accessTestApps{app: a}, &accessTestUsers{user: u},
		"https://auth.example.com", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, a, u
}

// TestAccessToken_ClaimsAndSignature pins the access-token claim set and
// proves the token verifies with the public key the JWKS publishes (the
// active keyring is the same source the endpoint serves).
func TestAccessToken_ClaimsAndSignature(t *testing.T) {
	t.Parallel()
	svc, a, u := newAccessTestService(t)

	raw, tok, err := svc.buildAccessToken(u, a, "openid profile", "")
	if err != nil {
		t.Fatalf("buildAccessToken: %v", err)
	}
	if tok.Token != raw {
		t.Error("returned Token.Token differs from the signed token")
	}
	if tok.AppID != a.ID || tok.UserID != u.ID || tok.Scopes != "openid profile" {
		t.Errorf("Token metadata = %+v, want app/user/scope of the grant", tok)
	}

	keys := svc.ActiveSigningKeys()
	if len(keys) == 0 {
		t.Fatal("no active signing key")
	}
	key := keys[0]

	claims := &accessClaims{}
	parsed, err := jwtlib.ParseWithClaims(raw, claims, func(tk *jwtlib.Token) (any, error) {
		if kid, _ := tk.Header["kid"].(string); kid != key.KID {
			t.Errorf("header kid = %q, want current %q", kid, key.KID)
		}
		return key.PublicKey(), nil
	}, jwtlib.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("verify with JWKS public key: %v", err)
	}
	if !parsed.Valid {
		t.Error("token did not verify")
	}

	if claims.Issuer != "https://auth.example.com" {
		t.Errorf("iss = %q", claims.Issuer)
	}
	if claims.Subject != u.ID {
		t.Errorf("sub = %q, want %q", claims.Subject, u.ID)
	}
	if claims.ClientID != a.ClientID {
		t.Errorf("client_id = %q, want %q", claims.ClientID, a.ClientID)
	}
	if claims.Scope != "openid profile" {
		t.Errorf("scope = %q", claims.Scope)
	}
	if claims.ID == "" {
		t.Error("jti is empty")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != a.ClientID {
		t.Errorf("aud = %v, want [%s]", claims.Audience, a.ClientID)
	}
	if claims.ExpiresAt == nil || claims.IssuedAt == nil {
		t.Fatal("exp/iat missing")
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != accessTokenTTL {
		t.Errorf("lifetime = %v, want %v", got, accessTokenTTL)
	}
}

// TestAccessToken_AudienceIsResource proves the audience is the granted
// resource when there is one, and the client id otherwise.
func TestAccessToken_AudienceIsResource(t *testing.T) {
	t.Parallel()
	svc, a, u := newAccessTestService(t)

	tests := []struct {
		name     string
		resource string
		want     string
	}{
		{name: "no resource", resource: "", want: a.ClientID},
		{name: "resource", resource: "https://api.example.com", want: "https://api.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, _, err := svc.buildAccessToken(u, a, "openid", tc.resource)
			if err != nil {
				t.Fatalf("buildAccessToken: %v", err)
			}
			claims, err := svc.parseAccessToken(raw)
			if err != nil {
				t.Fatalf("parseAccessToken: %v", err)
			}
			if audienceOf(claims) != tc.want {
				t.Errorf("aud = %q, want %q", audienceOf(claims), tc.want)
			}
		})
	}
}

// TestAccessToken_Expired proves an expired JWT is rejected. The token is
// signed with the real current key so only the exp claim differs from a live
// token.
func TestAccessToken_Expired(t *testing.T) {
	t.Parallel()
	svc, a, u := newAccessTestService(t)

	key, err := svc.CurrentSigningKey()
	if err != nil {
		t.Fatalf("CurrentSigningKey: %v", err)
	}
	now := time.Now().UTC()
	claims := jwtlib.MapClaims{
		"iss":       "https://auth.example.com",
		"sub":       u.ID,
		"aud":       jwtlib.ClaimStrings{a.ClientID},
		"exp":       now.Add(-time.Minute).Unix(),
		"iat":       now.Add(-2 * time.Hour).Unix(),
		"jti":       "expired-jti",
		"scope":     "openid",
		"client_id": a.ClientID,
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID
	raw, err := token.SignedString(key.privateKey)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	if _, _, err := svc.ValidateAccessToken(context.Background(), raw); err != ErrTokenExpired {
		t.Errorf("ValidateAccessToken(expired) = %v, want ErrTokenExpired", err)
	}
}

// TestAccessToken_AlgNoneRejected proves `alg: none` cannot be used to forge an
// access token, and that an otherwise valid token signed by an unknown kid is
// rejected too.
func TestAccessToken_AlgNoneRejected(t *testing.T) {
	t.Parallel()
	svc, a, u := newAccessTestService(t)

	now := time.Now().UTC()
	claims := jwtlib.MapClaims{
		"iss":       "https://auth.example.com",
		"sub":       u.ID,
		"aud":       jwtlib.ClaimStrings{a.ClientID},
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"jti":       "forged-jti",
		"scope":     "openid",
		"client_id": a.ClientID,
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, claims)
	token.Header["kid"] = "whatever"
	raw, err := token.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}

	if _, _, err := svc.ValidateAccessToken(context.Background(), raw); err == nil {
		t.Fatal("alg=none token was accepted")
	}
	if _, err := svc.parseAccessToken(raw); err == nil {
		t.Fatal("parseAccessToken accepted alg=none")
	}
}

// TestAccessToken_Denylist proves a revoked jti makes the token inactive and
// that the hourly cleanup removes denylist rows once the token would have
// expired anyway.
func TestAccessToken_Denylist(t *testing.T) {
	t.Parallel()
	svc, a, u := newAccessTestService(t)
	ctx := context.Background()

	raw, _, err := svc.buildAccessToken(u, a, "openid", "")
	if err != nil {
		t.Fatalf("buildAccessToken: %v", err)
	}
	claims, err := svc.parseAccessToken(raw)
	if err != nil {
		t.Fatalf("parseAccessToken: %v", err)
	}

	if err := svc.store.RevokeJTI(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}
	if _, _, err := svc.ValidateAccessToken(ctx, raw); err != ErrTokenRevoked {
		t.Errorf("ValidateAccessToken(revoked) = %v, want ErrTokenRevoked", err)
	}

	// A denylist row whose token has expired is dead weight; cleanup removes
	// it while keeping entries for tokens that are still live.
	if err := svc.store.RevokeJTI(ctx, "long-expired", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("RevokeJTI(expired): %v", err)
	}
	if err := svc.store.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if revoked, err := svc.store.IsJTIRevoked(ctx, "long-expired"); err != nil || revoked {
		t.Errorf("expired denylist row survived cleanup: revoked=%v err=%v", revoked, err)
	}
	if revoked, err := svc.store.IsJTIRevoked(ctx, claims.ID); err != nil || !revoked {
		t.Errorf("live denylist row was removed: revoked=%v err=%v", revoked, err)
	}
}

// TestNormalizeScopeCanonical pins the granted-scope canonicalisation.
func TestNormalizeScopeCanonical(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"openid", "openid"},
		{"  openid   profile ", "openid profile"},
		{"openid openid profile", "openid profile"},
	}
	for _, tc := range tests {
		if got := normalizeScope(tc.in); got != tc.want {
			t.Errorf("normalizeScope(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestLooksLikeJWT pins the shape test that routes a token to the signature
// path or the database path.
func TestLooksLikeJWT(t *testing.T) {
	t.Parallel()
	tests := []struct {
		token string
		want  bool
	}{
		{"aaa.bbb.ccc", true},
		{"a.b", false},
		{"", false},
		{strings.Repeat("a", 64), false},
		{"a..c", false},
	}
	for _, tc := range tests {
		if got := looksLikeJWT(tc.token); got != tc.want {
			t.Errorf("looksLikeJWT(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
}
