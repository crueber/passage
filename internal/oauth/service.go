package oauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
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

// Service implements the OAuth2/OIDC business logic.
type Service struct {
	store      Store
	apps       appClient
	users      userReader
	privateKey *rsa.PrivateKey
	baseURL    string
	logger     *slog.Logger
}

// NewService constructs a Service, parsing the RSA private key PEM.
// Returns an error if the PEM cannot be decoded or parsed.
func NewService(store Store, apps appClient, users userReader, privateKeyPEM []byte, baseURL string, logger *slog.Logger) (*Service, error) {
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
		baseURL:    baseURL,
		logger:     logger,
	}, nil
}

// PrivateKey returns the RSA private key. Used by the handler to expose the
// public key in the JWKS endpoint.
func (s *Service) PrivateKey() *rsa.PrivateKey {
	return s.privateKey
}

// Authorize validates the OAuth2 authorization request and creates an
// authorization code if the user has access to the requesting app.
func (s *Service) Authorize(ctx context.Context, clientID, redirectURI, scope, state, userID string) (*Code, error) {
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

	// Normalize scope.
	if scope == "" {
		scope = "openid"
	}

	// Create authorization code.
	code := &Code{
		AppID:       a.ID,
		UserID:      userID,
		RedirectURI: redirectURI,
		Scopes:      scope,
		ExpiresAt:   time.Now().UTC().Add(10 * time.Minute),
	}
	if err := s.store.CreateCode(ctx, code); err != nil {
		return nil, fmt.Errorf("oauth authorize: create code: %w", err)
	}

	return code, nil
}

// ExchangeCode validates an authorization code and issues an access token,
// refresh token, and id_token.
func (s *Service) ExchangeCode(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenResponse, error) {
	// Look up the authorization code.
	codeRecord, err := s.store.GetCode(ctx, code)
	if err != nil {
		return nil, err // already a sentinel error (ErrCodeNotFound)
	}
	if codeRecord.UsedAt != nil {
		return nil, ErrCodeUsed
	}
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

	if a.ID != codeRecord.AppID {
		return nil, fmt.Errorf("oauth exchange code: client_id does not match code's app")
	}

	// Verify client secret.
	if err := bcrypt.CompareHashAndPassword([]byte(a.ClientSecretHash), []byte(clientSecret)); err != nil {
		return nil, app.ErrInvalidClientSecret
	}

	// Validate redirect_uri matches what was stored in the code.
	if redirectURI != codeRecord.RedirectURI {
		return nil, app.ErrRedirectURIMismatch
	}

	// Mark the code as used.
	if err := s.store.MarkCodeUsed(ctx, code); err != nil {
		return nil, fmt.Errorf("oauth exchange code: mark code used: %w", err)
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
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
	}
	if err := s.store.CreateToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("oauth exchange code: create token: %w", err)
	}

	// Create refresh token.
	refreshToken := &RefreshToken{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    codeRecord.Scopes,
		ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := s.store.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("oauth exchange code: create refresh token: %w", err)
	}

	// Build and sign the id_token JWT.
	idToken, err := s.buildIDToken(u, clientID)
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
	if rt.UsedAt != nil {
		return nil, ErrRefreshUsed
	}
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

	if a.ID != rt.AppID {
		return nil, fmt.Errorf("oauth refresh tokens: client_id does not match refresh token's app")
	}

	// Verify client secret.
	if err := bcrypt.CompareHashAndPassword([]byte(a.ClientSecretHash), []byte(clientSecret)); err != nil {
		return nil, app.ErrInvalidClientSecret
	}

	// Mark old refresh token as used (rotation).
	if err := s.store.MarkRefreshTokenUsed(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: mark refresh token used: %w", err)
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
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
	}
	if err := s.store.CreateToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: create token: %w", err)
	}

	// Create new refresh token (rotation).
	newRefreshToken := &RefreshToken{
		AppID:     a.ID,
		UserID:    u.ID,
		Scopes:    rt.Scopes,
		ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := s.store.CreateRefreshToken(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("oauth refresh tokens: create refresh token: %w", err)
	}

	// Build and sign new id_token JWT.
	idToken, err := s.buildIDToken(u, clientID)
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
func (s *Service) buildIDToken(u *user.User, clientID string) (string, error) {
	now := time.Now()
	claims := jwtlib.MapClaims{
		"iss":                s.baseURL,
		"sub":                u.ID,
		"aud":                jwtlib.ClaimStrings{clientID},
		"exp":                now.Add(1 * time.Hour).Unix(),
		"iat":                now.Unix(),
		"auth_time":          now.Unix(),
		"name":               u.Name,
		"email":              u.Email,
		"preferred_username": u.Username,
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}
	return signed, nil
}
