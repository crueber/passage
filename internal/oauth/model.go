package oauth

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors for OAuth-related operations.
var (
	ErrCodeNotFound    = errors.New("oauth: authorization code not found")
	ErrCodeExpired     = errors.New("oauth: authorization code has expired")
	ErrCodeUsed        = errors.New("oauth: authorization code has already been used")
	ErrTokenNotFound   = errors.New("oauth: access token not found")
	ErrTokenExpired    = errors.New("oauth: access token has expired")
	ErrRefreshNotFound = errors.New("oauth: refresh token not found")
	ErrRefreshExpired  = errors.New("oauth: refresh token has expired")
	ErrRefreshUsed     = errors.New("oauth: refresh token has already been used")
	ErrUserInactive    = errors.New("oauth: user account is not active")
	ErrAccessRevoked   = errors.New("oauth: user does not have access to this application")

	// ErrPKCEVerificationFailed is returned when the code_verifier does not match
	// the code_challenge that was stored at authorization time.
	ErrPKCEVerificationFailed = errors.New("oauth: pkce verification failed")

	// ErrInvalidIDTokenHint is returned when an id_token_hint presented at the
	// logout endpoint is not a token this server issued (bad signature, wrong
	// issuer, or no audience).
	ErrInvalidIDTokenHint = errors.New("oauth: invalid id_token_hint")

	// ErrRefreshTokenReuse is returned when an already-rotated refresh token is
	// presented again. The token family it belonged to has been revoked.
	ErrRefreshTokenReuse = errors.New("oauth: refresh token reuse detected")
)

// RefreshTokenReuseError reports a replayed refresh token, which indicates the
// credential was stolen (OAuth 2.1 §6.1). By the time it is returned the entire
// family has been deleted from the store.
//
// It deliberately carries no token material: AppID/UserID/FamilyID are opaque
// internal identifiers for event emission (authentication event logging is
// wired during integration) and are safe to log.
//
// Unwrap reports both ErrRefreshTokenReuse and ErrRefreshUsed so existing
// callers that treat a consumed token as "already used" keep working.
type RefreshTokenReuseError struct {
	AppID    string
	UserID   string
	FamilyID string
}

func (e *RefreshTokenReuseError) Error() string {
	return "oauth: refresh token reuse detected; token family revoked"
}

// Unwrap makes errors.Is match both the reuse sentinel and the older
// "already used" sentinel.
func (e *RefreshTokenReuseError) Unwrap() []error {
	return []error{ErrRefreshTokenReuse, ErrRefreshUsed}
}

// TokenInfo is the RFC 7662 introspection response for an active token.
// It never contains the token value itself. Fields tagged omitempty are
// omitted for inactive tokens, which are returned as {"active": false}.
type TokenInfo struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"` // "Bearer" or "refresh_token"
	Issuer    string `json:"iss,omitempty"`
	Audience  string `json:"aud,omitempty"`
}

// PKCEMethod identifies the code challenge transformation method per RFC 7636.
type PKCEMethod string

const (
	PKCEMethodS256 PKCEMethod = "S256"
)

// Code is a short-lived authorization code (10-minute TTL).
type Code struct {
	Code        string
	AppID       string
	UserID      string
	RedirectURI string
	Scopes      string
	Nonce       string
	AuthTime    time.Time

	// CodeChallenge is the PKCE code challenge sent by the client at authorization time.
	// Empty when the client did not use PKCE.
	CodeChallenge string
	// CodeChallengeMethod is "S256". Empty when CodeChallenge is empty.
	CodeChallengeMethod PKCEMethod

	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// Token is an opaque access token (1-hour TTL).
type Token struct {
	Token     string
	AppID     string
	UserID    string
	Scopes    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// RefreshToken is a long-lived single-use refresh token (30-day TTL).
// Every token in a rotation chain shares one FamilyID; replaying a used token
// revokes the whole family (reuse detection).
type RefreshToken struct {
	Token     string
	AppID     string
	UserID    string
	Scopes    string
	FamilyID  string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// TokenResponse is the JSON response body for the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // always "Bearer"
	ExpiresIn    int    `json:"expires_in"` // seconds
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// Store is the persistence interface for OAuth artifacts.
// Defined here, at the consumer boundary, per Go convention.
type Store interface {
	// Authorization codes
	CreateCode(ctx context.Context, code *Code) error
	GetCode(ctx context.Context, code string) (*Code, error)
	MarkCodeUsed(ctx context.Context, code string) error

	// Access tokens
	CreateToken(ctx context.Context, token *Token) error
	GetToken(ctx context.Context, token string) (*Token, error)
	DeleteToken(ctx context.Context, token string) error

	// Refresh tokens
	CreateRefreshToken(ctx context.Context, rt *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, token string) error
	// DeleteRefreshFamily removes every refresh token in a rotation family.
	// Used for revocation (RFC 7009) and reuse detection.
	DeleteRefreshFamily(ctx context.Context, familyID string) error

	// Cleanup
	DeleteExpired(ctx context.Context) error

	// OIDC RSA key — generated once at startup, persisted in oidc_config.
	// Returns the PEM-encoded private key and a stable kid derived from the
	// public key (base64url SHA-256 thumbprint per RFC 7638).
	GetOrCreateRSAKey(ctx context.Context) (privateKeyPEM []byte, kid string, err error)
}
