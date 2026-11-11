package oauth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/policy"
	"github.com/crueber/passage/internal/user"
)

// appClient is the minimal interface needed from the app package.
// Defined here at the consumer boundary, per Go convention.
type appClient interface {
	GetByClientID(ctx context.Context, clientID string) (*app.App, error)
	HasAccess(ctx context.Context, userID, appID string) (bool, error)
	// TokenAssignments resolves a user's app-scoped role names and effective
	// (direct plus role-inherited) group names for token claims.
	TokenAssignments(ctx context.Context, userID, appID string) (roles, groups []string, err error)
	// EvaluateAccess applies the app's access policy to the user at
	// authorization time. An error means the policy could not be evaluated and
	// must be treated as a denial.
	EvaluateAccess(ctx context.Context, a *app.App, userID string, isAdmin bool, clientIP string, now time.Time) (policy.Decision, error)
}

// userReader is the minimal interface needed from the user package.
// Defined here at the consumer boundary, per Go convention.
type userReader interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
}

// Token TTL constants for the OAuth2/OIDC flows.
const (
	authCodeTTL     = 10 * time.Minute
	accessTokenTTL  = 1 * time.Hour
	refreshTokenTTL = 30 * 24 * time.Hour
	idTokenTTL      = 1 * time.Hour
)

// Service implements the OAuth2/OIDC business logic.
type Service struct {
	store      Store
	apps       appClient
	users      userReader
	privateKey *rsa.PrivateKey
	keyID      string // kid for id_token header and JWKS
	baseURL    string
	logger     *slog.Logger
}

// NewService constructs a Service, parsing the RSA private key PEM.
// Returns an error if the PEM cannot be decoded or parsed.
func NewService(store Store, apps appClient, users userReader, privateKeyPEM []byte, kid, baseURL string, logger *slog.Logger) (*Service, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("oauth service: failed to decode RSA PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oauth service: parse RSA private key: %w", err)
	}

	return &Service{
		store:      store,
		apps:       apps,
		users:      users,
		privateKey: privateKey,
		keyID:      kid,
		baseURL:    baseURL,
		logger:     logger,
	}, nil
}

// PrivateKey returns the RSA private key. Used by the handler to expose the
// public key in the JWKS endpoint.
func (s *Service) PrivateKey() *rsa.PrivateKey {
	return s.privateKey
}

// KeyID returns the kid (key ID) for the RSA key. Used by the handler to
// include the kid in the JWKS endpoint and id_token header.
func (s *Service) KeyID() string {
	return s.keyID
}

// Authorize validates an authorization request and creates a code. clientIP is
// the browser's address at the authorization endpoint (used only by the app's
// access policy). It returns a *PolicyDenialError when the app's group, role,
// CIDR, admin-only, hour or day rules refuse the user.
func (s *Service) Authorize(ctx context.Context, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string, sessionCreatedAt time.Time, userID, clientIP string) (*Code, error) {
	// Look up app by clientID.
	a, err := s.apps.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return nil, app.ErrOAuthNotEnabled
		}
		return nil, fmt.Errorf("oauth authorize: get app by client id: %w", err)
	}

	if !a.OAuthEnabled {
		return nil, app.ErrOAuthNotEnabled
	}

	// Validate redirectURI: exact string match against registered URIs.
	matched := false
	for _, uri := range a.RedirectURIs {
		if uri == redirectURI {
			matched = true
			break
		}
	}
	if !matched {
		return nil, app.ErrRedirectURIMismatch
	}

	// Check that the user has access to this app.
	hasAccess, err := s.apps.HasAccess(ctx, userID, a.ID)
	if err != nil {
		return nil, fmt.Errorf("oauth authorize: check access: %w", err)
	}
	if !hasAccess {
		return nil, fmt.Errorf("oauth authorize: user does not have access to this application")
	}

	// Per-app access policy. Only apps that define a policy incur the extra
	// assignment and user lookups; an app with no policy authorizes exactly as
	// before. A malformed stored rule or an unparseable client address fails
	// closed with the same opaque error the client sees for any other policy
	// denial.
	if !a.Policy().IsEmpty() {
		u, err := s.users.GetByID(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("oauth authorize: load user for access policy: %w", err)
		}
		decision, err := s.apps.EvaluateAccess(ctx, a, userID, u.IsAdmin, clientIP, time.Now())
		if err != nil {
			return nil, fmt.Errorf("oauth authorize: evaluate access policy: %w", err)
		}
		if !decision.Allowed {
			return nil, &PolicyDenialError{AppSlug: a.Slug, Reason: decision.Reason}
		}
	}

	// Validate PKCE parameters per RFC 7636 §4.3.
	var pkceMethod PKCEMethod
	if codeChallenge != "" {
		switch codeChallengeMethod {
		case string(PKCEMethodS256):
			pkceMethod = PKCEMethodS256
		case "":
			// method omitted; default to S256 per RFC 7636 §4.3 ABNF default.
			pkceMethod = PKCEMethodS256
		default:
			// "plain" and anything else are rejected (OAuth 2.1 drops "plain":
			// the challenge is verifier-equivalent when observed in the
			// authorize request URL).
			return nil, fmt.Errorf("oauth authorize: unsupported code_challenge_method: %w", ErrPKCEVerificationFailed)
		}
		// Validate challenge length per RFC 7636 §4.2: S256 challenges are
		// always BASE64URL(SHA256(verifier)) = 43 chars.
		if len(codeChallenge) != 43 {
			return nil, fmt.Errorf("oauth authorize: S256 code_challenge must be 43 characters: %w", ErrPKCEVerificationFailed)
		}
	}

	// Normalize scope.
	if scope == "" {
		scope = "openid"
	}

	// Create authorization code.
	code := &Code{
		AppID:               a.ID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scope,
		Nonce:               nonce,
		AuthTime:            sessionCreatedAt.UTC(),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: pkceMethod,
		ExpiresAt:           time.Now().UTC().Add(authCodeTTL),
	}
	if err := s.store.CreateCode(ctx, code); err != nil {
		return nil, fmt.Errorf("oauth authorize: create code: %w", err)
	}

	return code, nil
}

// ExchangeCode validates an authorization code and issues an access token,
// refresh token, and id_token.
func (s *Service) ExchangeCode(ctx context.Context, code, clientID, clientSecret, redirectURI, codeVerifier string) (*TokenResponse, error) {
	// Look up the authorization code.
	codeRecord, err := s.store.GetCode(ctx, code)
	if err != nil {
		return nil, err // already a sentinel error (ErrCodeNotFound)
	}
	// Do not check UsedAt here — MarkCodeUsed handles double-spend atomically.
	if time.Now().UTC().After(codeRecord.ExpiresAt) {
		return nil, ErrCodeExpired
	}

	// Look up app by clientID and verify it matches the code's app.
	a, err := s.apps.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return nil, app.ErrOAuthNotEnabled
		}
		return nil, fmt.Errorf("oauth exchange code: get app: %w", err)
	}

	// Check app ID before bcrypt to avoid an expensive hash on wrong client.
	if a.ID != codeRecord.AppID {
		return nil, fmt.Errorf("oauth exchange code: client_id does not match code's app")
	}

	// Verify PKCE challenge if one was stored with this code.
	// This must run before the client secret check because PKCE public clients
	// may not have a client_secret — the code_verifier IS their proof of identity.
	if err := verifyPKCE(codeRecord.CodeChallenge, codeRecord.CodeChallengeMethod, codeVerifier); err != nil {
		return nil, err
	}

	// Verify client secret — required for confidential clients (no PKCE).
	// When PKCE was used, the code_verifier already proved client possession;
	// the secret check is skipped per RFC 7636 §4.6.
	if codeRecord.CodeChallenge == "" {
		if err := bcrypt.CompareHashAndPassword([]byte(a.ClientSecretHash), []byte(clientSecret)); err != nil {
			return nil, app.ErrInvalidClientSecret
		}
	}

	// Validate redirect_uri matches what was stored in the code.
	if redirectURI != codeRecord.RedirectURI {
		return nil, app.ErrRedirectURIMismatch
	}

	// Atomically mark the code as used — returns ErrCodeUsed on double-spend.
	if err := s.store.MarkCodeUsed(ctx, code); err != nil {
		return nil, err
	}

	// Look up the user.
	u, err := s.users.GetByID(ctx, codeRecord.UserID)
	if err != nil {
		return nil, fmt.Errorf("oauth exchange code: get user: %w", err)
	}

	// Re-check account state and app access at exchange time. The code was
	// minted at authorize time (up to 10 minutes earlier) and the code has
	// already been consumed, so a rejected exchange burns the code.
	if !u.IsActive {
		return nil, ErrUserInactive
	}
	hasAccess, err := s.apps.HasAccess(ctx, u.ID, a.ID)
	if err != nil {
		return nil, fmt.Errorf("oauth exchange code: check access: %w", err)
	}
	if !hasAccess {
		return nil, ErrAccessRevoked
	}

	// Create access token.
	accessToken := &Token{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    codeRecord.Scopes,
		ExpiresAt: time.Now().UTC().Add(accessTokenTTL),
	}
	if err := s.store.CreateToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("oauth exchange code: create token: %w", err)
	}

	// Create refresh token. FamilyID is left empty so the store starts a new
	// rotation family for this grant.
	refreshToken := &RefreshToken{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    codeRecord.Scopes,
		ExpiresAt: time.Now().UTC().Add(refreshTokenTTL),
	}
	if err := s.store.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("oauth exchange code: create refresh token: %w", err)
	}

	// Build and sign the id_token JWT.
	idToken, err := s.buildIDToken(ctx, u, a.ID, clientID, codeRecord.AuthTime, codeRecord.Nonce)
	if err != nil {
		return nil, fmt.Errorf("oauth exchange code: build id token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken.Token,
		IDToken:      idToken,
		Scope:        codeRecord.Scopes,
	}, nil
}

// RefreshTokens validates a refresh token and issues a new access token,
// new refresh token (rotation), and new id_token. The old refresh token is
// marked as used and cannot be reused.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenResponse, error) {
	// Look up the refresh token.
	rt, err := s.store.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err // already a sentinel error (ErrRefreshNotFound)
	}
	// Do not check UsedAt here — MarkRefreshTokenUsed handles double-spend atomically.
	if time.Now().UTC().After(rt.ExpiresAt) {
		return nil, ErrRefreshExpired
	}

	// Look up app by clientID and verify.
	a, err := s.apps.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return nil, app.ErrOAuthNotEnabled
		}
		return nil, fmt.Errorf("oauth refresh tokens: get app: %w", err)
	}

	// Check app ID before bcrypt to avoid an expensive hash on wrong client.
	if a.ID != rt.AppID {
		return nil, fmt.Errorf("oauth refresh tokens: client_id does not match refresh token's app")
	}

	// Verify client secret.
	if err := bcrypt.CompareHashAndPassword([]byte(a.ClientSecretHash), []byte(clientSecret)); err != nil {
		return nil, app.ErrInvalidClientSecret
	}

	// Reuse detection (OAuth 2.1 §6.1). A refresh token is single-use: once it
	// has been rotated, presenting it again can only mean the value leaked, so
	// the whole rotation family is revoked and the request is rejected with
	// invalid_grant. This check runs after client authentication on purpose —
	// otherwise anyone holding a stale token value could destroy a live family
	// without knowing the client secret. The sentinel wraps ErrRefreshUsed as
	// well, so "already used" callers see the same class of failure.
	if rt.UsedAt != nil {
		if err := s.store.DeleteRefreshFamily(ctx, rt.FamilyID); err != nil {
			return nil, fmt.Errorf("oauth refresh tokens: delete reused family: %w", err)
		}
		return nil, &RefreshTokenReuseError{
			AppID:    rt.AppID,
			UserID:   rt.UserID,
			FamilyID: rt.FamilyID,
		}
	}

	// Atomically mark old refresh token as used (rotation) — returns ErrRefreshUsed on double-spend.
	if err := s.store.MarkRefreshTokenUsed(ctx, refreshToken); err != nil {
		return nil, err
	}

	// Look up the user.
	u, err := s.users.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: get user: %w", err)
	}

	// Deactivated users must not be able to mint new tokens. This check runs
	// AFTER MarkRefreshTokenUsed so a rejected refresh burns the refresh token
	// and terminates the rotation chain.
	if !u.IsActive {
		return nil, ErrUserInactive
	}

	// Revoked app access must terminate the token chain as well; access was
	// only checked at authorize time, which can be up to 30 days in the past.
	hasAccess, err := s.apps.HasAccess(ctx, u.ID, a.ID)
	if err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: check access: %w", err)
	}
	if !hasAccess {
		return nil, ErrAccessRevoked
	}

	// Create new access token.
	accessToken := &Token{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    rt.Scopes,
		ExpiresAt: time.Now().UTC().Add(accessTokenTTL),
	}
	if err := s.store.CreateToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: create token: %w", err)
	}

	// Create new refresh token (rotation). The child inherits the parent's
	// family_id so a replay of any token in the chain revokes the chain.
	newRefreshToken := &RefreshToken{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    rt.Scopes,
		FamilyID:  rt.FamilyID,
		ExpiresAt: time.Now().UTC().Add(refreshTokenTTL),
	}
	if err := s.store.CreateRefreshToken(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: create refresh token: %w", err)
	}

	// Build and sign new id_token JWT.
	// On refresh, nonce is not re-issued (OIDC spec: nonce is only in the initial id_token).
	// auth_time is omitted: the original authentication time is not persisted on refresh
	// tokens, and using rt.CreatedAt would be misleading (it reflects token issuance, not
	// the user's actual authentication event). Omitting auth_time is safer per OIDC Core §2.
	idToken, err := s.buildIDToken(ctx, u, a.ID, clientID, time.Time{}, "")
	if err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: build id token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: newRefreshToken.Token,
		IDToken:      idToken,
		Scope:        rt.Scopes,
	}, nil
}

// ValidateAccessToken looks up an access token and returns the associated user
// and token record. Returns ErrTokenNotFound or ErrTokenExpired on failure.
func (s *Service) ValidateAccessToken(ctx context.Context, token string) (*user.User, *Token, error) {
	t, err := s.store.GetToken(ctx, token)
	if err != nil {
		return nil, nil, err // already a sentinel error (ErrTokenNotFound)
	}

	if time.Now().UTC().After(t.ExpiresAt) {
		return nil, nil, ErrTokenExpired
	}

	u, err := s.users.GetByID(ctx, t.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth validate access token: get user: %w", err)
	}

	// A deactivated account's outstanding tokens must stop working immediately,
	// matching session.ValidateSession semantics.
	if !u.IsActive {
		return nil, nil, ErrUserInactive
	}

	return u, t, nil
}

// authenticateClient resolves an OAuth client and verifies its secret.
// It is the shared client-authentication path for the token, revocation, and
// introspection endpoints. The returned errors are the app package sentinels
// (ErrOAuthNotEnabled, ErrInvalidClientSecret) so callers can map them to
// invalid_client; anything else is an internal failure.
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (*app.App, error) {
	if clientID == "" {
		return nil, app.ErrOAuthNotEnabled
	}
	a, err := s.apps.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return nil, app.ErrOAuthNotEnabled
		}
		return nil, fmt.Errorf("oauth client auth: get app: %w", err)
	}
	if !a.OAuthEnabled {
		return nil, app.ErrOAuthNotEnabled
	}
	if err := bcrypt.CompareHashAndPassword([]byte(a.ClientSecretHash), []byte(clientSecret)); err != nil {
		return nil, app.ErrInvalidClientSecret
	}
	return a, nil
}

// ClientForIDTokenHint verifies that idTokenHint was signed by this server and
// returns the app named by its aud claim. The signature is checked against the
// live signing key with RS256 only; claim *timestamps* are not validated
// because OIDC RP-Initiated Logout 1.0 §2 allows an expired id_token as a hint
// (the RP may be logging out a session whose token has already expired).
// Nothing else from the hint is trusted.
func (s *Service) ClientForIDTokenHint(ctx context.Context, idTokenHint string) (*app.App, error) {
	claims := jwtlib.MapClaims{}
	_, err := jwtlib.ParseWithClaims(idTokenHint, claims, func(t *jwtlib.Token) (any, error) {
		// Reject any algorithm confusion (e.g. HS256 signed with the public key).
		if _, ok := t.Method.(*jwtlib.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		return &s.privateKey.PublicKey, nil
	}, jwtlib.WithValidMethods([]string{"RS256"}), jwtlib.WithoutClaimsValidation())
	if err != nil {
		// The parse error is not returned to the client; it is kept in the
		// wrapped chain for logs while the sentinel drives the response.
		return nil, fmt.Errorf("oauth verify id token hint: %w: %w", err, ErrInvalidIDTokenHint)
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

// Token kinds used by the revocation and introspection endpoints. They match
// the token_type_hint values defined by RFC 7009 §2.1 and RFC 7662 §2.1 and the
// token_type values returned by introspection.
const (
	tokenKindAccess  = "access_token"
	tokenKindRefresh = "refresh_token"
)

// tokenKinds returns the token types to try, in order, for a request that
// carries an optional token_type_hint. The hint is advisory: if the hinted type
// does not hold the token, the other type is still tried.
func tokenKinds(tokenTypeHint string) []string {
	switch tokenTypeHint {
	case tokenKindRefresh:
		return []string{tokenKindRefresh, tokenKindAccess}
	default:
		return []string{tokenKindAccess, tokenKindRefresh}
	}
}

// RevokeToken implements RFC 7009 token revocation. Revoking a refresh token
// revokes its whole rotation family; revoking an access token deletes that one
// token. Unknown tokens, tokens owned by a different client, and hints that do
// not match are all silent no-ops so the endpoint never reveals whether a token
// exists. Only client authentication failures are reported to the caller.
func (s *Service) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	a, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	if token == "" {
		return nil
	}

	for _, kind := range tokenKinds(tokenTypeHint) {
		if kind == tokenKindAccess {
			t, err := s.store.GetToken(ctx, token)
			if err != nil {
				if errors.Is(err, ErrTokenNotFound) {
					continue
				}
				return fmt.Errorf("oauth revoke: get access token: %w", err)
			}
			if t.AppID != a.ID {
				// Another client's token: report success without touching it.
				return nil
			}
			if err := s.store.DeleteToken(ctx, token); err != nil {
				return fmt.Errorf("oauth revoke: delete access token: %w", err)
			}
			return nil
		}

		rt, err := s.store.GetRefreshToken(ctx, token)
		if err != nil {
			if errors.Is(err, ErrRefreshNotFound) {
				continue
			}
			return fmt.Errorf("oauth revoke: get refresh token: %w", err)
		}
		if rt.AppID != a.ID {
			return nil
		}
		if err := s.store.DeleteRefreshFamily(ctx, rt.FamilyID); err != nil {
			return fmt.Errorf("oauth revoke: delete refresh family: %w", err)
		}
		return nil
	}
	return nil
}

// IntrospectToken implements RFC 7662 token introspection. It returns nil for
// any token that is unknown, expired, used, owned by a different client, or
// whose user is deactivated — the handler renders that as {"active": false}.
// The token value itself is never echoed back. Only client authentication
// failures and infrastructure errors are reported to the caller.
func (s *Service) IntrospectToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*TokenInfo, error) {
	a, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, nil
	}

	for _, kind := range tokenKinds(tokenTypeHint) {
		if kind == tokenKindAccess {
			t, err := s.store.GetToken(ctx, token)
			if err != nil {
				if errors.Is(err, ErrTokenNotFound) {
					continue
				}
				return nil, fmt.Errorf("oauth introspect: get access token: %w", err)
			}
			if t.AppID != a.ID || time.Now().UTC().After(t.ExpiresAt) {
				return nil, nil
			}
			u, err := s.users.GetByID(ctx, t.UserID)
			if err != nil {
				return nil, fmt.Errorf("oauth introspect: get user: %w", err)
			}
			if !u.IsActive {
				return nil, nil
			}
			return s.tokenInfo(a, u, t.Scopes, t.CreatedAt, t.ExpiresAt, "Bearer"), nil
		}

		rt, err := s.store.GetRefreshToken(ctx, token)
		if err != nil {
			if errors.Is(err, ErrRefreshNotFound) {
				continue
			}
			return nil, fmt.Errorf("oauth introspect: get refresh token: %w", err)
		}
		if rt.AppID != a.ID || rt.UsedAt != nil || time.Now().UTC().After(rt.ExpiresAt) {
			return nil, nil
		}
		u, err := s.users.GetByID(ctx, rt.UserID)
		if err != nil {
			return nil, fmt.Errorf("oauth introspect: get user: %w", err)
		}
		if !u.IsActive {
			return nil, nil
		}
		return s.tokenInfo(a, u, rt.Scopes, rt.CreatedAt, rt.ExpiresAt, tokenKindRefresh), nil
	}
	return nil, nil
}

// tokenInfo assembles the RFC 7662 response for an active token.
func (s *Service) tokenInfo(a *app.App, u *user.User, scope string, issuedAt, expiresAt time.Time, tokenType string) *TokenInfo {
	return &TokenInfo{
		Active:    true,
		ClientID:  a.ClientID,
		Username:  u.Username,
		Subject:   u.ID,
		Scope:     scope,
		ExpiresAt: expiresAt.Unix(),
		IssuedAt:  issuedAt.Unix(),
		TokenType: tokenType,
		Issuer:    s.baseURL,
		Audience:  a.ClientID,
	}
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

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}
	return signed, nil
}

// verifyPKCE checks that verifier satisfies challenge per RFC 7636 §4.6.
// Returns nil if verification succeeds, ErrPKCEVerificationFailed otherwise.
//
// Rules:
//   - If challenge is empty: the code was issued without PKCE; verifier must also be empty.
//   - If challenge is non-empty: verifier must be non-empty and must satisfy the challenge.
//   - method S256:  BASE64URL(SHA256(ASCII(verifier))) == challenge
//   - method plain: verifier == challenge
func verifyPKCE(challenge string, method PKCEMethod, verifier string) error {
	if challenge == "" {
		// Code was issued without PKCE. No verifier expected.
		if verifier != "" {
			return ErrPKCEVerificationFailed
		}
		return nil
	}
	// Code was issued with PKCE. Verifier is required.
	if verifier == "" {
		return ErrPKCEVerificationFailed
	}
	switch method {
	case PKCEMethodS256:
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
			return ErrPKCEVerificationFailed
		}
	default:
		// Unknown method stored in DB — fail closed.
		return ErrPKCEVerificationFailed
	}
	return nil
}

// TokenAssignments resolves a user's app-scoped role names and effective
// group names (direct plus role-inherited) for token claims and the
// userinfo response. Delegates to the app service.
func (s *Service) TokenAssignments(ctx context.Context, userID, appID string) (roles, groups []string, err error) {
	return s.apps.TokenAssignments(ctx, userID, appID)
}
