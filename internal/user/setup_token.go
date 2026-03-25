package user

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// SetupTokenManager holds a single in-memory setup token that is valid for
// a limited time and consumed on use. It is created at startup if no admin
// user exists and is invalidated once the first admin account is created via
// the /setup endpoint or when it expires.
//
// The manager is safe for concurrent use.
type SetupTokenManager struct {
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewSetupTokenManager generates a new setup token with a 1-hour expiry and
// returns the manager alongside the plaintext token so the caller can log it.
// The token is 32 bytes of crypto/rand encoded as hex (64 characters).
func NewSetupTokenManager() (*SetupTokenManager, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, "", fmt.Errorf("generate setup token: %w", err)
	}
	token := hex.EncodeToString(b)
	m := &SetupTokenManager{
		token:     token,
		expiresAt: time.Now().UTC().Add(1 * time.Hour),
	}
	return m, token, nil
}

// Consume validates the provided token. If it matches, has not expired, and
// has not already been consumed, it marks the token as used and returns true.
// Returns false in all other cases — wrong token, expired, already used, or nil receiver.
func (m *SetupTokenManager) Consume(token string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.token == "" {
		return false
	}
	if time.Now().UTC().After(m.expiresAt) {
		m.token = ""
		return false
	}
	if token != m.token {
		return false
	}
	// Consume — invalidate after single use.
	m.token = ""
	return true
}

// IsActive reports whether the token is still valid (not yet consumed and not
// expired). Returns false for a nil receiver.
func (m *SetupTokenManager) IsActive() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token != "" && time.Now().UTC().Before(m.expiresAt)
}
