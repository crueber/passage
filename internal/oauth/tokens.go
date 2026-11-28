package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/user"
)

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

	// Look up app by clientID and verify OAuth is enabled and matches the code's app.
	a, err := s.loadOAuthApp(ctx, "oauth exchange code", clientID)
	if err != nil {
		return nil, err
	}

	// Check app ID before bcrypt to avoid an expensive hash on wrong client.
	// Wrap ErrCodeNotFound so the token endpoint returns 400 invalid_grant
	// rather than 500 server_error (avoiding a cross-client code oracle).
	if a.ID != codeRecord.AppID {
		return nil, fmt.Errorf("oauth exchange code: client_id does not match code's app: %w", ErrCodeNotFound)
	}

	// Verify PKCE challenge if one was stored with this code.
	// This must run before the client secret check because PKCE public clients
	// may not have a client_secret — the code_verifier IS their proof of identity.
	if err := verifyPKCE(codeRecord.CodeChallenge, codeRecord.CodeChallengeMethod, codeVerifier); err != nil {
		return nil, err
	}

	// Verify client secret — required for confidential clients (no PKCE), and
	// also verified whenever a PKCE client explicitly supplies a client_secret
	// so a wrong secret is never silently ignored.
	if codeRecord.CodeChallenge == "" || clientSecret != "" {
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
	if err := s.enforceAccessPolicy(ctx, a, u.ID, u, clientIP); err != nil {
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
		ExpiresIn:    int(accessTokenTTL.Seconds()),
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

	// Look up app by clientID and verify OAuth is enabled.
	a, err := s.loadOAuthApp(ctx, "oauth refresh tokens", clientID)
	if err != nil {
		return nil, err
	}

	// Check app ID before bcrypt to avoid an expensive hash on wrong client.
	// Wrap ErrRefreshNotFound so the token endpoint returns 400 invalid_grant.
	if a.ID != rt.AppID {
		return nil, fmt.Errorf("oauth refresh tokens: client_id does not match refresh token's app: %w", ErrRefreshNotFound)
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
	// without knowing the client secret.
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

	// Validate client-supplied scope and resource BEFORE burning the refresh
	// token so a malformed parameter does not destroy a healthy rotation chain.
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
	grantedResource, err := resolveResource(a, resource)
	if err != nil {
		return nil, err
	}

	// Atomically mark old refresh token as used (rotation). A concurrent replay
	// that lost the race sees ErrRefreshUsed here and revokes the family just
	// like a sequential replay.
	if err := s.store.MarkRefreshTokenUsed(ctx, refreshToken); err != nil {
		if errors.Is(err, ErrRefreshUsed) {
			if delErr := s.store.DeleteRefreshFamily(ctx, rt.FamilyID); delErr != nil {
				return nil, fmt.Errorf("oauth refresh tokens: delete concurrently reused family: %w", delErr)
			}
			return nil, &RefreshTokenReuseError{
				AppID:    rt.AppID,
				UserID:   rt.UserID,
				FamilyID: rt.FamilyID,
			}
		}
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
	if err := s.enforceAccessPolicy(ctx, a, u.ID, u, clientIP); err != nil {
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
		ExpiresIn:    int(accessTokenTTL.Seconds()),
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
	a, err := s.loadOAuthApp(ctx, "oauth client auth", clientID)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(a.ClientSecretHash), []byte(clientSecret)); err != nil {
		return nil, app.ErrInvalidClientSecret
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
				if errors.Is(err, user.ErrNotFound) {
					return nil, nil
				}
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
			if errors.Is(err, user.ErrNotFound) {
				return nil, nil
			}
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
