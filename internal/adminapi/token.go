// Package adminapi implements Passage's read-only administrative REST API and
// the bearer tokens that authenticate it.
//
// The API is mounted under /api/v1 and is deliberately read-only: there is no
// endpoint that changes state. A token is an administrator credential — treat
// it like a password. Only its SHA-256 hex digest is stored; the plaintext is
// shown once at creation and cannot be recovered.
package adminapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	// TokenPrefix marks a Passage API token. It makes a leaked token
	// recognisable in logs and secret scanners without revealing anything.
	TokenPrefix = "pst_"

	// tokenRandomBytes is the entropy behind a token. 32 bytes (256 bits) is
	// well beyond guessing range even against an offline hash search, which is
	// why a plain SHA-256 digest is an adequate storage form.
	tokenRandomBytes = 32
)

var (
	// ErrTokenNotFound reports an unknown or revoked token. The two cases are
	// deliberately indistinguishable to the caller.
	ErrTokenNotFound = errors.New("adminapi: token not found")

	// ErrNameRequired reports a token creation attempt without a name.
	ErrNameRequired = errors.New("adminapi: token name is required")
)

// Token is one API token as stored. TokenHash is the SHA-256 hex digest of the
// plaintext token; the plaintext itself is never persisted.
type Token struct {
	ID        string
	Name      string
	TokenHash string
	CreatedAt time.Time
	// LastUsedAt is the last successful use. The zero value means "never used".
	LastUsedAt time.Time
	// RevokedAt is the revocation time. The zero value means "still valid".
	RevokedAt time.Time
}

// Revoked reports whether the token has been revoked.
func (t *Token) Revoked() bool {
	return !t.RevokedAt.IsZero()
}

// GenerateToken returns a new plaintext token and the hash to store. The
// plaintext is returned to the caller exactly once and must not be logged.
func GenerateToken() (plaintext, hash string, err error) {
	b := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate api token: %w", err)
	}
	plaintext = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return plaintext, HashToken(plaintext), nil
}

// HashToken returns the lowercase hex SHA-256 digest of a token, which is the
// lookup key in the database. Hash lookup is inherently constant-time with
// respect to the presented value: an attacker cannot learn a stored token byte
// by byte from response timing.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
