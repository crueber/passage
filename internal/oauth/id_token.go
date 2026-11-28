package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/user"
)

// ClientForIDTokenHint verifies that idTokenHint was signed by this server and
// returns the app named by its aud claim. The signature is checked against the
// key named by the token's kid — any non-retired key, so a hint issued before a
// rotation still verifies — with RS256 only. Claim *timestamps* are not
// validated because OIDC RP-Initiated Logout 1.0 §2 allows an expired id_token
// as a hint (the RP may be logging out a session whose token has already
// expired). Nothing else from the hint is trusted.
func (s *Service) ClientForIDTokenHint(ctx context.Context, idTokenHint string) (*app.App, error) {
	claims := jwtlib.MapClaims{}
	_, err := jwtlib.ParseWithClaims(idTokenHint, claims, s.verifySigningKey,
		jwtlib.WithValidMethods([]string{"RS256"}), jwtlib.WithoutClaimsValidation())
	if err != nil {
		// The parse error is not returned to the client; it is kept in the
		// wrapped chain for logs while the sentinel drives the response.
		return nil, fmt.Errorf("oauth verify id token hint: %w: %w", err, ErrInvalidIDTokenHint)
	}

	// Access tokens are signed by the same key and issuer, so shape alone does
	// not tell them apart. A jti is an access-token claim (id_tokens have
	// none): refuse one here so an access token cannot act as a logout hint.
	if _, isAccessToken := claims["jti"]; isAccessToken {
		return nil, fmt.Errorf("oauth verify id token hint: access token presented as hint: %w", ErrInvalidIDTokenHint)
	}

	issuer, err := claims.GetIssuer()
	if err != nil || issuer != s.baseURL {
		return nil, fmt.Errorf("oauth verify id token hint: issuer mismatch: %w", ErrInvalidIDTokenHint)
	}

	audience, err := claims.GetAudience()
	if err != nil || len(audience) == 0 {
		return nil, fmt.Errorf("oauth verify id token hint: missing audience: %w", ErrInvalidIDTokenHint)
	}

	a, err := s.apps.GetByClientID(ctx, audience[0])
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return nil, fmt.Errorf("oauth verify id token hint: unknown client: %w", ErrInvalidIDTokenHint)
		}
		return nil, fmt.Errorf("oauth verify id token hint: get app: %w", err)
	}
	return a, nil
}

// buildIDToken constructs and signs a JWT id_token using RS256.
// authTime is the time the user originally authenticated (session creation time).
// When authTime is the zero value, the auth_time claim is omitted — this is
// the correct behaviour on token refresh where the original auth time is not
// available (OIDC Core §2, auth_time is OPTIONAL).
// nonce is the OIDC nonce from the authorization request; it is included in the
// claims only when non-empty (OIDC Core §3.1.3.6).
// The app-scoped "roles" and "groups" claims are always present as arrays:
// groups are the user's effective memberships (direct plus role-inherited)
// resolved at issuance time, scoped to the app the token is issued for.
func (s *Service) buildIDToken(ctx context.Context, u *user.User, appID, clientID string, authTime time.Time, nonce string) (string, error) {
	now := time.Now().UTC()
	claims := jwtlib.MapClaims{
		"iss":                s.baseURL,
		"sub":                u.ID,
		"aud":                jwtlib.ClaimStrings{clientID},
		"exp":                now.Add(idTokenTTL).Unix(),
		"iat":                now.Unix(),
		"name":               u.Name,
		"email":              u.Email,
		"preferred_username": u.Username,
		"is_admin":           u.IsAdmin,
		// email_verified reports the stored flag, which verification links
		// set. It is never used to gate authentication (a broken mail server
		// must not lock anyone out); clients that require a verified address
		// can enforce that themselves.
		"email_verified": u.EmailVerified,
	}
	// auth_time is included only when the original authentication time is known.
	// On token refresh, authTime is zero and the claim is deliberately omitted.
	if !authTime.IsZero() {
		claims["auth_time"] = authTime.Unix()
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	// App-scoped role and group claims. Groups are effective (direct plus
	// role-inherited) memberships resolved at issuance time. Both claims are
	// always present as arrays so clients can rely on their shape; they are
	// empty when the user has no assignments for this app.
	roles, groups, err := s.apps.TokenAssignments(ctx, u.ID, appID)
	if err != nil {
		return "", fmt.Errorf("oauth build id token: resolve assignments: %w", err)
	}
	claims["roles"] = roles
	claims["groups"] = groups

	key, err := s.CurrentSigningKey()
	if err != nil {
		return "", fmt.Errorf("oauth build id token: %w", err)
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID
	signed, err := token.SignedString(key.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}
	return signed, nil
}

// TokenAssignments resolves a user's app-scoped role names and effective
// group names (direct plus role-inherited) for token claims and the
// userinfo response. Delegates to the app service.
func (s *Service) TokenAssignments(ctx context.Context, userID, appID string) (roles, groups []string, err error) {
	return s.apps.TokenAssignments(ctx, userID, appID)
}
