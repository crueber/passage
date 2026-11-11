package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
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
	store   Store
	apps    appClient
	users   userReader
	baseURL string
	logger  *slog.Logger

	// keys holds an immutable keyring snapshot. Rotation installs a new
	// snapshot atomically, so a request never observes a half-built ring.
	keys atomic.Pointer[Keyring]
}

// NewService constructs a Service and loads the OIDC signing keyring.
//
// It ensures at least one signing key exists (importing the legacy single key
// on first start), so a Service is never constructed without a usable key.
func NewService(ctx context.Context, store Store, apps appClient, users userReader, baseURL string, logger *slog.Logger) (*Service, error) {
	s := &Service{
		store:   store,
		apps:    apps,
		users:   users,
		baseURL: baseURL,
		logger:  logger,
	}
	if err := store.EnsureSigningKeys(ctx); err != nil {
		return nil, fmt.Errorf("oauth service: ensure signing keys: %w", err)
	}
	if err := s.ReloadSigningKeys(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// ReloadSigningKeys rebuilds the keyring from the store and installs it.
// Called at startup and after every rotation, retirement, or deletion.
func (s *Service) ReloadSigningKeys(ctx context.Context) error {
	keys, err := s.store.ListSigningKeys(ctx)
	if err != nil {
		return fmt.Errorf("oauth service: list signing keys: %w", err)
	}
	ring, err := newKeyring(keys)
	if err != nil {
		return fmt.Errorf("oauth service: build keyring: %w", err)
	}
	s.keys.Store(ring)
	return nil
}

// keyring returns the current snapshot, or nil before the first load.
func (s *Service) keyring() *Keyring {
	return s.keys.Load()
}

// ActiveSigningKeys returns the non-retired keys, newest first. These are
// served by the JWKS endpoint and accepted for verification.
func (s *Service) ActiveSigningKeys() []*SigningKey {
	return s.keyring().Active()
}

// CurrentSigningKey returns the key that signs new id_tokens: the newest
// non-retired key.
func (s *Service) CurrentSigningKey() (*SigningKey, error) {
	key := s.keyring().Current()
	if key == nil {
		return nil, ErrNoSigningKey
	}
	return key, nil
}

// ListSigningKeys returns the full key history for the admin UI, newest first.
func (s *Service) ListSigningKeys(ctx context.Context) ([]*SigningKey, error) {
	keys, err := s.store.ListSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauth service: list signing keys: %w", err)
	}
	return keys, nil
}

// RotateSigningKey generates a new 2048-bit RSA key and makes it current. The
// previous key is left active so every id_token it signed keeps verifying
// until it expires; retiring it is a separate, explicit action.
func (s *Service) RotateSigningKey(ctx context.Context) (*SigningKey, error) {
	key, err := generateSigningKey()
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateSigningKey(ctx, key); err != nil {
		return nil, fmt.Errorf("oauth service: rotate signing key: %w", err)
	}
	if err := s.ReloadSigningKeys(ctx); err != nil {
		return nil, err
	}
	s.logger.Info("oauth signing key rotated", "kid", key.KID)
	return key, nil
}

// RetireSigningKey stops a key being served and accepted. The last active key
// cannot be retired.
func (s *Service) RetireSigningKey(ctx context.Context, kid string) error {
	if err := s.store.RetireSigningKey(ctx, kid); err != nil {
		return fmt.Errorf("oauth service: retire signing key: %w", err)
	}
	if err := s.ReloadSigningKeys(ctx); err != nil {
		return err
	}
	s.logger.Info("oauth signing key retired", "kid", kid)
	return nil
}

// DeleteSigningKey removes a retired key permanently.
func (s *Service) DeleteSigningKey(ctx context.Context, kid string) error {
	if err := s.store.DeleteSigningKey(ctx, kid); err != nil {
		return fmt.Errorf("oauth service: delete signing key: %w", err)
	}
	if err := s.ReloadSigningKeys(ctx); err != nil {
		return err
	}
	s.logger.Info("oauth signing key deleted", "kid", kid)
	return nil
}

// enforceAccessPolicy applies the app's per-app access policy to a token
// grant. It is shared by authorize, code exchange, and refresh so a policy an
// administrator adds after a code or refresh token was issued cannot be
// outlived by it: refresh chains live for weeks, which is far longer than an
// incident response. An app with no policy returns immediately, before any
// assignment or user lookup.
func (s *Service) enforceAccessPolicy(ctx context.Context, a *app.App, userID, clientIP string) error {
	if a.Policy().IsEmpty() {
		return nil
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("oauth enforce access policy: load user: %w", err)
	}
	decision, err := s.apps.EvaluateAccess(ctx, a, userID, u.IsAdmin, clientIP, time.Now())
	if err != nil {
		return fmt.Errorf("oauth enforce access policy: evaluate: %w", err)
	}
	if !decision.Allowed {
		return &PolicyDenialError{
			AppSlug:  a.Slug,
			Reason:   decision.Reason,
			UserID:   u.ID,
			Username: u.Username,
		}
	}
	return nil
}

// Authorize validates an authorization request and creates a code. clientIP is
// the browser's address at the authorization endpoint (used only by the app's
// access policy). resource is the RFC 8707 resource indicator, or "" when the
// client requested none.
//
// It returns a *PolicyDenialError when the app's group, role, CIDR, admin-only,
// hour or day rules refuse the user, ErrInvalidScope when the request escalates
// beyond the app's scope registry, and ErrInvalidTarget when a resource
// indicator is not one of the app's registered audiences. No code is created in
// any of those cases.
func (s *Service) Authorize(ctx context.Context, clientID, redirectURI, scope, resource, state, nonce, codeChallenge, codeChallengeMethod string, sessionCreatedAt time.Time, userID, clientIP string) (*Code, error) {
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
	if err := checkRedirectURI(a, redirectURI); err != nil {
		return nil, err
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
	if err := s.enforceAccessPolicy(ctx, a, userID, clientIP); err != nil {
		return nil, err
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

	// Normalize the requested scope and enforce the app's scope registry.
	// An empty registry keeps the pre-registry behaviour: whatever the client
	// asks for is granted, and an absent scope still means openid.
	scope = normalizeScope(scope)
	if scope == "" {
		scope = "openid"
	}
	if err := validateRequestedScopes(a.AllowedScopes, scope); err != nil {
		return nil, err
	}

	// Validate the RFC 8707 resource indicator. The granted audience is stored
	// with the code so the token endpoint cannot issue a token for a different
	// one.
	grantedResource, err := resolveResource(a, resource)
	if err != nil {
		return nil, err
	}

	// Create authorization code.
	code := &Code{
		AppID:               a.ID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scope,
		Resource:            grantedResource,
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

// checkRedirectURI reports whether redirectURI is one of the app's registered
// redirect URIs. The comparison is an exact string match: no prefix, suffix, or
// wildcard matching.
func checkRedirectURI(a *app.App, redirectURI string) error {
	for _, uri := range a.RedirectURIs {
		if uri == redirectURI {
			return nil
		}
	}
	return app.ErrRedirectURIMismatch
}

// ValidateClientRedirectURI performs the client and redirect_uri checks of
// Authorize without issuing a code. It exists for authorization requests that
// must be answered before a session is resolved (prompt=none, which may not
// show UI): an error response may only be redirected to a redirect_uri that is
// registered to the client, otherwise the endpoint would be an open
// redirector. The sentinels are the same ones Authorize returns.
func (s *Service) ValidateClientRedirectURI(ctx context.Context, clientID, redirectURI string) error {
	a, err := s.apps.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return app.ErrOAuthNotEnabled
		}
		return fmt.Errorf("oauth validate client redirect: get app by client id: %w", err)
	}
	if !a.OAuthEnabled {
		return app.ErrOAuthNotEnabled
	}
	return checkRedirectURI(a, redirectURI)
}

// ExchangeCode validates an authorization code and issues a JWT access token,
// refresh token, and id_token. resource is the RFC 8707 resource indicator
// echoed by the client, or "" when it sent none; when present it must match the
// audience granted at authorization time.
func (s *Service) ExchangeCode(ctx context.Context, code, clientID, clientSecret, redirectURI, codeVerifier, resource, clientIP string) (*TokenResponse, error) {
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

	// Re-check the access policy as well: the code was minted up to ten
	// minutes ago, and an administrator may have tightened the app since.
	// Like a revoked grant, a denial here burns the code (it is already
	// marked used above).
	if err := s.enforceAccessPolicy(ctx, a, u.ID, clientIP); err != nil {
		return nil, err
	}

	// Create access token. The audience is the resource granted at authorize
	// time (re-validated against the current registry), otherwise the client
	// id. The scope is re-checked as well: an admin may have tightened the
	// registry since the code was issued, and the code must not outlive that.
	grantedScope := normalizeScope(codeRecord.Scopes)
	if grantedScope == "" {
		grantedScope = "openid"
	}
	if err := validateRequestedScopes(a.AllowedScopes, grantedScope); err != nil {
		return nil, err
	}
	grantedResource, err := reconcileResource(a, codeRecord.Resource, resource)
	if err != nil {
		return nil, err
	}
	_, accessToken, err := s.buildAccessToken(u, a, grantedScope, grantedResource)
	if err != nil {
		return nil, fmt.Errorf("oauth exchange code: issue access token: %w", err)
	}

	// Create refresh token. FamilyID is left empty so the store starts a new
	// rotation family for this grant.
	refreshToken := &RefreshToken{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    grantedScope,
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
		Scope:        grantedScope,
	}, nil
}

// RefreshTokens validates a refresh token and issues a new access token,
// new refresh token (rotation), and new id_token. The old refresh token is
// marked as used and cannot be reused.
//
// resource is the RFC 8707 resource indicator for the new access token (empty
// means none); scope optionally narrows the grant and must be a subset of the
// refresh token's scopes. Neither may exceed the app's registries.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken, clientID, clientSecret, resource, scope, clientIP string) (*TokenResponse, error) {
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

	// Access policies are re-evaluated here for the same reason as the grant
	// above: a refresh chain can outlive the authorization by weeks, so a
	// policy added since must terminate it. The client IP is the one making
	// this request, which is what a CIDR rule is about.
	if err := s.enforceAccessPolicy(ctx, a, u.ID, clientIP); err != nil {
		return nil, err
	}

	// Work out the scope of the new grant. A refresh may narrow the original
	// scope (RFC 6749 §6) but never widen it, and an app registry that has
	// since been tightened still applies.
	grantedScope := normalizeScope(scope)
	if grantedScope == "" {
		grantedScope = normalizeScope(rt.Scopes)
		if grantedScope == "" {
			grantedScope = "openid"
		}
	} else if !scopeSubset(grantedScope, rt.Scopes) {
		return nil, fmt.Errorf("oauth refresh tokens: requested scope exceeds the refresh grant: %w", ErrInvalidScope)
	}
	if err := validateRequestedScopes(a.AllowedScopes, grantedScope); err != nil {
		return nil, err
	}

	// The refresh token does not carry the original resource, so the audience
	// is whatever the client asks for now: none (the client id) or one of the
	// app's registered resources.
	grantedResource, err := resolveResource(a, resource)
	if err != nil {
		return nil, err
	}

	// Create new access token.
	_, accessToken, err := s.buildAccessToken(u, a, grantedScope, grantedResource)
	if err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: issue access token: %w", err)
	}

	// Create new refresh token (rotation). The child inherits the parent's
	// family_id so a replay of any token in the chain revokes the chain.
	newRefreshToken := &RefreshToken{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    grantedScope,
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
		Scope:        grantedScope,
	}, nil
}

// ValidateAccessToken resolves an access token and returns the associated user
// and token record. Returns ErrTokenNotFound, ErrTokenExpired, ErrTokenRevoked,
// or ErrUserInactive on failure.
//
// A JWT is verified against the current keyring (RS256 only) and the
// revocation denylist. An opaque token already in oauth_tokens keeps the
// database path, so sessions issued before JWTs existed survive an upgrade
// without forcing anyone to sign in again.
func (s *Service) ValidateAccessToken(ctx context.Context, token string) (*user.User, *Token, error) {
	if looksLikeJWT(token) {
		return s.validateJWTAccessToken(ctx, token)
	}

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
// revokes its whole rotation family; revoking an opaque access token deletes
// that one row; revoking a JWT access token denylists its jti. Unknown tokens,
// tokens owned by a different client, and hints that do not match are all
// silent no-ops so the endpoint never reveals whether a token exists. Only
// client authentication failures are reported to the caller.
func (s *Service) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	a, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	if token == "" {
		return nil
	}
	// A JWT is shape-distinguishable, and the hint is advisory, so its
	// revocation path does not depend on token_type_hint.
	if looksLikeJWT(token) {
		return s.revokeJWTAccessToken(ctx, a, token)
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
// any token that is unknown, expired, used, revoked, owned by a different
// client, or whose user is deactivated — the handler renders that as
// {"active": false}. Both JWT and opaque access tokens are supported. The
// token value itself is never echoed back. Only client authentication failures
// and infrastructure errors are reported to the caller.
func (s *Service) IntrospectToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*TokenInfo, error) {
	a, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, nil
	}
	if looksLikeJWT(token) {
		return s.introspectJWTAccessToken(ctx, a, token)
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
			return s.tokenInfo(a, u, t.Scopes, t.CreatedAt, t.ExpiresAt, "Bearer", a.ClientID), nil
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
		return s.tokenInfo(a, u, rt.Scopes, rt.CreatedAt, rt.ExpiresAt, tokenKindRefresh, a.ClientID), nil
	}
	return nil, nil
}

// tokenInfo assembles the RFC 7662 response for an active token. audience is
// the resource the token was granted for, or the client id when there is none.
func (s *Service) tokenInfo(a *app.App, u *user.User, scope string, issuedAt, expiresAt time.Time, tokenType, audience string) *TokenInfo {
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
		Audience:  audience,
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
