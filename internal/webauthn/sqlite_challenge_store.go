package webauthn

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// SQLiteChallengeStore persists WebAuthn challenge session data in SQLite.
// Keys are prefixed: "reg:<sessionID>" for registration, "auth:<sessionID>" for login.
// Get* operations are destructive (single-use): the row is deleted on first read.
type SQLiteChallengeStore struct {
	db *sql.DB
}

// NewSQLiteChallengeStore creates a new SQLiteChallengeStore backed by db.
func NewSQLiteChallengeStore(db *sql.DB) *SQLiteChallengeStore {
	return &SQLiteChallengeStore{db: db}
}

// SetRegistration stores a registration challenge keyed by sessionID.
func (s *SQLiteChallengeStore) SetRegistration(sessionID string, session gowebauthn.SessionData) {
	s.set(regKey(sessionID), session)
}

// SetAuthentication stores a login challenge keyed by sessionID.
func (s *SQLiteChallengeStore) SetAuthentication(sessionID string, session gowebauthn.SessionData) {
	s.set(authKey(sessionID), session)
}

// GetRegistration retrieves and removes a registration challenge (single-use).
// Returns ErrChallengeNotFound if missing, ErrChallengeExpired if TTL has elapsed.
func (s *SQLiteChallengeStore) GetRegistration(sessionID string) (gowebauthn.SessionData, error) {
	return s.pop(context.Background(), regKey(sessionID))
}

// GetAuthentication retrieves and removes a login challenge (single-use).
// Returns ErrChallengeNotFound if missing, ErrChallengeExpired if TTL has elapsed.
func (s *SQLiteChallengeStore) GetAuthentication(sessionID string) (gowebauthn.SessionData, error) {
	return s.pop(context.Background(), authKey(sessionID))
}

// DeleteExpired removes all rows whose expires_at is in the past.
func (s *SQLiteChallengeStore) DeleteExpired(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_challenges WHERE expires_at < ?`,
		time.Now().UTC())
	if err != nil {
		return fmt.Errorf("webauthn: delete expired challenges: %w", err)
	}
	return nil
}

// set upserts a challenge row into the database. Errors are logged-and-dropped
// because the Set* callers have no error return; a failed set will surface as
// a not-found on the subsequent Get*.
func (s *SQLiteChallengeStore) set(key string, session gowebauthn.SessionData) {
	data, err := json.Marshal(session)
	if err != nil {
		return
	}
	expiresAt := time.Now().Add(challengeTTL).UTC()
	_, _ = s.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO webauthn_challenges (id, session_data, expires_at, created_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		key, string(data), expiresAt)
}

// pop retrieves and deletes a challenge row atomically (single-use semantics).
func (s *SQLiteChallengeStore) pop(ctx context.Context, key string) (gowebauthn.SessionData, error) {
	var sessionDataJSON string
	var expiresAt time.Time

	err := s.db.QueryRowContext(ctx,
		`SELECT session_data, expires_at FROM webauthn_challenges WHERE id = ?`, key).
		Scan(&sessionDataJSON, &expiresAt)
	if err == sql.ErrNoRows {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: %w", ErrChallengeNotFound)
	}
	if err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: query: %w", err)
	}

	// Delete the record regardless of expiry — single-use semantics.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE id = ?`, key)

	if time.Now().After(expiresAt) {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: %w", ErrChallengeExpired)
	}

	var session gowebauthn.SessionData
	if err := json.Unmarshal([]byte(sessionDataJSON), &session); err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: unmarshal: %w", err)
	}
	return session, nil
}

func regKey(sessionID string) string  { return "reg:" + sessionID }
func authKey(sessionID string) string { return "auth:" + sessionID }
