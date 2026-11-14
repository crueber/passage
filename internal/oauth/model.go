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

	// ErrTokenRevoked is returned when a JWT access token's jti is in the
	// revocation denylist. It is distinct from ErrTokenNotFound so logs can
	// tell a revoked token from an unknown one; both are a 401 to the client.
	ErrTokenRevoked = errors.New("oauth: access token has been revoked")

	// ErrInvalidScope is returned when a request asks for a scope the client
	// is not registered for. No authorization code or token is issued.
	ErrInvalidScope = errors.New("oauth: requested scope is not allowed")

	// ErrInvalidTarget is returned when an RFC 8707 resource indicator is
	// malformed or is not one of the client's registered audiences. No
	// authorization code or token is issued.
	ErrInvalidTarget = errors.New("oauth: resource indicator is not allowed")

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

	// ErrAccessDeniedByPolicy is returned at authorization time when the app's
	// access policy (group/role/CIDR/admin-only/hours/days) refuses the user.
	// The handler maps it to the OAuth access_denied error with a fixed
	// description, so the specific rule never reaches the client.
	ErrAccessDeniedByPolicy = errors.New("oauth: access denied by application policy")

	// ErrNoSigningKey is returned when the keyring has no usable (non-retired)
	// RSA key. It is a broken-invariant error: startup imports or generates a
	// key, and retiring the only active key is refused.
	ErrNoSigningKey = errors.New("oauth: no active signing key")

	// ErrSigningKeyNotFound is returned when a kid does not name a stored key.
	ErrSigningKeyNotFound = errors.New("oauth: signing key not found")

	// ErrSigningKeyActive is returned when deleting a key that is still active.
	// Only retired keys may be deleted, so history is never lost by accident.
	ErrSigningKeyActive = errors.New("oauth: signing key is still active")

	// ErrSigningKeyLast is returned when retiring the only non-retired key.
	// Rotating first keeps the issuer able to sign at all times.
	ErrSigningKeyLast = errors.New("oauth: cannot retire the only active signing key")
)

// PolicyDenialError names the policy rule that denied an authorization request.
// Reason is a short token from internal/policy (for example "group" or "hours")
// and carries no user data; AppSlug identifies the app for the event log.
type PolicyDenialError struct {
	AppSlug string
	Reason  string
	// UserID and Username identify the denied user so the security event
	// names them. They carry no credential material.
	UserID   string
	Username string
}

func (e *PolicyDenialError) Error() string {
	return "oauth: access denied by application policy: app=" + e.AppSlug + " reason=" + e.Reason
}

// Unwrap makes errors.Is(err, ErrAccessDeniedByPolicy) hold for every denial.
func (e *PolicyDenialError) Unwrap() error { return ErrAccessDeniedByPolicy }

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

	// Resource is the RFC 8707 audience granted at authorization time, or
	// empty when the client requested none. The token endpoint issues an
	// access token for this audience, so the code and the token cannot
	// disagree about who the token is for.
	Resource string

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

	// JWT access-token revocation denylist. A jti is kept only until the
	// token would have expired; DeleteExpired removes those rows.
	RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) error
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)

	// Refresh tokens
	CreateRefreshToken(ctx context.Context, rt *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, token string) error
	// DeleteRefreshFamily removes every refresh token in a rotation family.
	// Used for revocation (RFC 7009) and reuse detection.
	DeleteRefreshFamily(ctx context.Context, familyID string) error

	// Cleanup
	DeleteExpired(ctx context.Context) error

	// OIDC signing keys (kid history).
	//
	// EnsureSigningKeys imports the legacy oidc_config key when the ring is
	// empty and generates a key when there is none at all; it is idempotent and
	// called at startup.
	EnsureSigningKeys(ctx context.Context) error
	// ListSigningKeys returns every key, newest first, retired keys included.
	// Each key carries its parsed private key for signing and verification.
	ListSigningKeys(ctx context.Context) ([]*SigningKey, error)
	// CreateSigningKey persists key and fills in KID (derived from the public
	// key) and CreatedAt.
	CreateSigningKey(ctx context.Context, key *SigningKey) error
	// RetireSigningKey marks a key retired. It refuses the only active key so
	// the issuer can always sign.
	RetireSigningKey(ctx context.Context, kid string) error
	// DeleteSigningKey removes a retired key. Active keys cannot be deleted.
	DeleteSigningKey(ctx context.Context, kid string) error
}
