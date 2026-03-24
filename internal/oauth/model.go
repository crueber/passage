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
)

// Code is a short-lived authorization code (10-minute TTL).
type Code struct {
	Code        string
	AppID       string
	UserID      string
	RedirectURI string
	Scopes      string
	ExpiresAt   time.Time
	UsedAt      *time.Time
	CreatedAt   time.Time
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
type RefreshToken struct {
	Token     string
	AppID     string
	UserID    string
	Scopes    string
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

	// Cleanup
	DeleteExpired(ctx context.Context) error

	// OIDC RSA key — generated once at startup, persisted in oidc_config
	GetOrCreateRSAKey(ctx context.Context) (privateKeyPEM []byte, err error)
}
