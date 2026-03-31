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
	"github.com/crueber/passage/internal/user"
)

// appClient is the minimal interface needed from the app package.
// Defined here at the consumer boundary, per Go convention.
type appClient interface {
	GetByClientID(ctx context.Context, clientID string) (*app.App, error)
	HasAccess(ctx context.Context, userID, appID string) (bool, error)
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

// Authorize validates the OAuth2 authorization request and creates an
// authorization code if the user has access to the requesting app.
func (s *Service) Authorize(ctx context.Context, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string, sessionCreatedAt time.Time, userID string) (*Code, error) {
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

	// Validate PKCE parameters per RFC 7636 §4.3.
	var pkceMethod PKCEMethod
	if codeChallenge != "" {
		switch codeChallengeMethod {
		case string(PKCEMethodS256):
			pkceMethod = PKCEMethodS256
		case string(PKCEMethodPlain):
			pkceMethod = PKCEMethodPlain
		case "":
			// method omitted; default to S256 per RFC 7636 §4.3 ABNF default.
			pkceMethod = PKCEMethodS256
		default:
			return nil, fmt.Errorf("oauth authorize: unsupported code_challenge_method: %w", ErrPKCEVerificationFailed)
		}
		// Validate challenge length per RFC 7636 §4.2.
		switch pkceMethod {
		case PKCEMethodS256:
			// S256 challenge is always BASE64URL(SHA256(verifier)): 32 bytes → exactly 43 chars.
			if len(codeChallenge) != 43 {
				return nil, fmt.Errorf("oauth authorize: S256 code_challenge must be 43 characters: %w", ErrPKCEVerificationFailed)
			}
		case PKCEMethodPlain:
			// Plain challenge == verifier; RFC 7636 §4.1 range: 43-128 chars.
			if l := len(codeChallenge); l < 43 || l > 128 {
				return nil, fmt.Errorf("oauth authorize: plain code_challenge length must be 43-128 characters: %w", ErrPKCEVerificationFailed)
			}
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

	// Create refresh token.
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
	idToken, err := s.buildIDToken(u, clientID, codeRecord.AuthTime, codeRecord.Nonce)
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

	// Atomically mark old refresh token as used (rotation) — returns ErrRefreshUsed on double-spend.
	if err := s.store.MarkRefreshTokenUsed(ctx, refreshToken); err != nil {
		return nil, err
	}

	// Look up the user.
	u, err := s.users.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: get user: %w", err)
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

	// Create new refresh token (rotation).
	newRefreshToken := &RefreshToken{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    rt.Scopes,
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
	idToken, err := s.buildIDToken(u, clientID, time.Time{}, "")
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

	return u, t, nil
}

// buildIDToken constructs and signs a JWT id_token using RS256.
// authTime is the time the user originally authenticated (session creation time).
// When authTime is the zero value, the auth_time claim is omitted — this is
// the correct behaviour on token refresh where the original auth time is not
// available (OIDC Core §2, auth_time is OPTIONAL).
// nonce is the OIDC nonce from the authorization request; it is included in the
// claims only when non-empty (OIDC Core §3.1.3.6).
func (s *Service) buildIDToken(u *user.User, clientID string, authTime time.Time, nonce string) (string, error) {
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
		// email_verified is required by OIDC Core §5.1. Passage is a
		// self-hosted IdP where all accounts are admin-created, so all
		// stored addresses are considered administratively verified.
		"email_verified": true,
	}
	// auth_time is included only when the original authentication time is known.
	// On token refresh, authTime is zero and the claim is deliberately omitted.
	if !authTime.IsZero() {
		claims["auth_time"] = authTime.Unix()
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

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
	case PKCEMethodPlain:
		if subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) != 1 {
			return ErrPKCEVerificationFailed
		}
	default:
		// Unknown method stored in DB — fail closed.
		return ErrPKCEVerificationFailed
	}
	return nil
}
