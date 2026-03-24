package webauthn

import (
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

const challengeTTL = 5 * time.Minute

// challengeEntry holds a WebAuthn session along with its expiry time.
type challengeEntry struct {
	session   gowebauthn.SessionData
	expiresAt time.Time
}

// ChallengeStore is an in-memory store for WebAuthn session data (challenges).
// Each entry expires after ttl to prevent replay attacks.
// Keys are prefixed: "reg:<sessionID>" for registration, "auth:<sessionID>" for login.
type ChallengeStore struct {
	mu      sync.Mutex
	entries map[string]*challengeEntry
	ttl     time.Duration
}

// NewChallengeStore creates a new, empty ChallengeStore with the default TTL.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		entries: make(map[string]*challengeEntry),
		ttl:     challengeTTL,
	}
}

// NewChallengeStoreWithTTL creates a ChallengeStore with a custom TTL (for testing).
func NewChallengeStoreWithTTL(ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{entries: make(map[string]*challengeEntry), ttl: ttl}
}

// SetRegistration stores a registration challenge keyed by sessionID.
func (s *ChallengeStore) SetRegistration(sessionID string, session gowebauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries["reg:"+sessionID] = &challengeEntry{
		session:   session,
		expiresAt: time.Now().Add(s.ttl),
	}
}

// GetRegistration retrieves and removes a registration challenge.
// Returns ErrChallengeNotFound if the key is missing or expired.
func (s *ChallengeStore) GetRegistration(sessionID string) (gowebauthn.SessionData, error) {
	return s.pop("reg:" + sessionID)
}

// SetAuthentication stores a login challenge keyed by sessionID.
func (s *ChallengeStore) SetAuthentication(sessionID string, session gowebauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries["auth:"+sessionID] = &challengeEntry{
		session:   session,
		expiresAt: time.Now().Add(s.ttl),
	}
}

// GetAuthentication retrieves and removes a login challenge.
// Returns ErrChallengeNotFound if the key is missing or expired.
func (s *ChallengeStore) GetAuthentication(sessionID string) (gowebauthn.SessionData, error) {
	return s.pop("auth:" + sessionID)
}

// pop retrieves and deletes an entry, checking TTL.
func (s *ChallengeStore) pop(key string) (gowebauthn.SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: %w", ErrChallengeNotFound)
	}
	delete(s.entries, key)

	if time.Now().After(entry.expiresAt) {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: %w", ErrChallengeExpired)
	}

	return entry.session, nil
}

// Cleanup removes all expired entries from the store.
// Call periodically to prevent unbounded memory growth.
func (s *ChallengeStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, key)
		}
	}
}

// sessionIDFromChallenge creates a URL-safe session key from a WebAuthn challenge string.
// The challenge is already base64url-encoded by go-webauthn; we re-encode it to be safe.
func sessionIDFromChallenge(challenge string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(challenge))
}
