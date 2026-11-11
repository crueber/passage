package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/user"
)

// accessClaims are the claims of a JWT access token. A token is an access
// token (and not, say, an id_token signed by the same key) when it carries a
// client_id and a jti: id_tokens have neither.
type accessClaims struct {
	// Scope is the granted scope, space delimited (RFC 8693 §4.2 uses the same
	// claim name; RFC 9068 §2.2 makes it a string).
	Scope string `json:"scope"`
	// ClientID is the client the token was issued to. The audience is the
	// resource when one was granted, so the client id needs its own claim.
	ClientID string `json:"client_id"`

	jwtlib.RegisteredClaims
}

// looksLikeJWT reports whether raw has the compact JWS shape. Passage's opaque
// tokens are 64 hex characters with no dots, so there is no ambiguity: an
// opaque token always takes the database path and a JWS always takes the
// signature path.
func looksLikeJWT(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// verifySigningKey resolves the key a presented JWS was signed with. Only a
// non-retired kid is accepted, so retiring a key immediately stops the tokens
// it signed from verifying. The caller restricts the algorithm to RS256, which
// also defeats an HS256 token that tries to use the public key as an HMAC
// secret (algorithm confusion).
func (s *Service) verifySigningKey(t *jwtlib.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	key, ok := s.keyring().ByKID(kid)
	if !ok {
		return nil, fmt.Errorf("unknown or retired kid %q", kid)
	}
	return key.PublicKey(), nil
}

// parseAccessToken verifies an access token's signature, algorithm, and
// issuer, and requires the access-token claims. Claim *timestamps* are not
// validated here so the revocation path can read the jti of an expired token;
// callers that need liveness check ExpiresAt themselves.
func (s *Service) parseAccessToken(raw string) (*accessClaims, error) {
	claims := &accessClaims{}
	_, err := jwtlib.ParseWithClaims(raw, claims, s.verifySigningKey,
		jwtlib.WithValidMethods([]string{"RS256"}),
		jwtlib.WithoutClaimsValidation())
	if err != nil {
		return nil, fmt.Errorf("verify access token: %w", err)
	}
	if claims.Issuer != s.baseURL {
		return nil, fmt.Errorf("verify access token: issuer %q is not %q", claims.Issuer, s.baseURL)
	}
	if claims.ClientID == "" || claims.ID == "" || claims.Subject == "" {
		return nil, errors.New("verify access token: missing access-token claims")
	}
	return claims, nil
}

// buildAccessToken signs an RS256 JWT access token with the current signing
// key — the same key and kid that sign id_tokens and are published in the
// JWKS. The audience is the granted resource, or the client id when the client
// did not request one. The returned Token carries the same metadata an opaque
// token row would, so callers can treat both shapes alike.
func (s *Service) buildAccessToken(u *user.User, a *app.App, scope, resource string) (string, *Token, error) {
	audience := strings.TrimSpace(resource)
	if audience == "" {
		audience = a.ClientID
	}

	jti, err := generateToken()
	if err != nil {
		return "", nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(accessTokenTTL)
	claims := jwtlib.MapClaims{
		"iss":       s.baseURL,
		"sub":       u.ID,
		"aud":       jwtlib.ClaimStrings{audience},
		"exp":       expiresAt.Unix(),
		"iat":       now.Unix(),
		"jti":       jti,
		"scope":     scope,
		"client_id": a.ClientID,
	}

	key, err := s.CurrentSigningKey()
	if err != nil {
		return "", nil, fmt.Errorf("oauth build access token: %w", err)
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID
	signed, err := token.SignedString(key.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("sign access token: %w", err)
	}

	return signed, &Token{
		Token:     signed,
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    scope,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}, nil
}

// validateJWTAccessToken verifies a JWT access token and returns the user and
// a synthetic Token record. It is the JWT half of ValidateAccessToken; opaque
// tokens already in oauth_tokens keep the database path.
func (s *Service) validateJWTAccessToken(ctx context.Context, raw string) (*user.User, *Token, error) {
	claims, err := s.parseAccessToken(raw)
	if err != nil {
		// The real reason is kept in the wrapped chain for logs; the caller
		// only needs to know the token is not usable.
		return nil, nil, fmt.Errorf("oauth validate access token: %w: %w", err, ErrTokenNotFound)
	}
	if claims.ExpiresAt == nil {
		return nil, nil, fmt.Errorf("oauth validate access token: missing exp: %w", ErrTokenNotFound)
	}
	if time.Now().UTC().After(claims.ExpiresAt.Time) {
		return nil, nil, ErrTokenExpired
	}

	revoked, err := s.store.IsJTIRevoked(ctx, claims.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth validate access token: check revocation: %w", err)
	}
	if revoked {
		return nil, nil, ErrTokenRevoked
	}

	u, err := s.users.GetByID(ctx, claims.Subject)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth validate access token: get user: %w", err)
	}
	if !u.IsActive {
		return nil, nil, ErrUserInactive
	}

	a, err := s.apps.GetByClientID(ctx, claims.ClientID)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			// The client was deleted; its tokens are no longer usable.
			return nil, nil, fmt.Errorf("oauth validate access token: unknown client: %w", ErrTokenNotFound)
		}
		return nil, nil, fmt.Errorf("oauth validate access token: get app: %w", err)
	}

	issuedAt := claims.ExpiresAt.Time
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}
	return u, &Token{
		Token:     raw,
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    claims.Scope,
		ExpiresAt: claims.ExpiresAt.Time,
		CreatedAt: issuedAt,
	}, nil
}

// introspectJWTAccessToken implements RFC 7662 for a JWT access token. A nil
// result means inactive, exactly like a missing, expired, or used opaque row.
func (s *Service) introspectJWTAccessToken(ctx context.Context, client *app.App, raw string) (*TokenInfo, error) {
	claims, err := s.parseAccessToken(raw)
	if err != nil {
		return nil, nil
	}
	// Introspection is only answered for the client the token was issued to.
	if claims.ClientID != client.ClientID || claims.ExpiresAt == nil {
		return nil, nil
	}
	if time.Now().UTC().After(claims.ExpiresAt.Time) {
		return nil, nil
	}

	revoked, err := s.store.IsJTIRevoked(ctx, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("oauth introspect: check revocation: %w", err)
	}
	if revoked {
		return nil, nil
	}

	u, err := s.users.GetByID(ctx, claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("oauth introspect: get user: %w", err)
	}
	if !u.IsActive {
		return nil, nil
	}

	issuedAt := claims.ExpiresAt.Time
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}
	return s.tokenInfo(client, u, claims.Scope, issuedAt, claims.ExpiresAt.Time, "Bearer", audienceOf(claims)), nil
}

// revokeJWTAccessToken denylists a JWT access token so both introspection and
// userinfo report it inactive. The denylist row only lives until the token
// would have expired. A token that does not verify, or belongs to another
// client, is a silent no-op: RFC 7009 must not reveal token state.
func (s *Service) revokeJWTAccessToken(ctx context.Context, client *app.App, raw string) error {
	claims, err := s.parseAccessToken(raw)
	if err != nil {
		return nil
	}
	if claims.ClientID != client.ClientID {
		return nil
	}

	expiresAt := time.Now().UTC().Add(accessTokenTTL)
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	if err := s.store.RevokeJTI(ctx, claims.ID, expiresAt); err != nil {
		return fmt.Errorf("oauth revoke: denylist access token: %w", err)
	}
	return nil
}

// audienceOf returns the access token's audience, or the client id when the
// aud claim is absent.
func audienceOf(claims *accessClaims) string {
	if claims == nil {
		return ""
	}
	if len(claims.Audience) == 0 {
		return claims.ClientID
	}
	return claims.Audience[0]
}
