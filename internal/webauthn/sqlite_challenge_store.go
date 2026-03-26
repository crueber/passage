package webauthn

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// SQLiteChallengeStore persists WebAuthn challenge session data in SQLite.
// Keys are prefixed: "reg:<sessionID>" for registration, "auth:<sessionID>" for login.
// Get* operations are destructive (single-use): the row is deleted on first read.
type SQLiteChallengeStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewSQLiteChallengeStore creates a new SQLiteChallengeStore backed by db.
func NewSQLiteChallengeStore(db *sql.DB, logger *slog.Logger) *SQLiteChallengeStore {
	return &SQLiteChallengeStore{db: db, logger: logger}
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

// set upserts a challenge row into the database. Errors are dropped (Set*
// callers have no error return) but logged as warnings so operators can
// diagnose missing challenges. A failed set surfaces as ErrChallengeNotFound
// on the subsequent Get*.
func (s *SQLiteChallengeStore) set(key string, session gowebauthn.SessionData) {
	data, err := json.Marshal(session)
	if err != nil {
		s.logger.Warn("webauthn challenge: marshal failed; challenge will not be stored",
			"key", key, "error", err)
		return
	}
	expiresAt := time.Now().Add(challengeTTL).UTC()
	if _, err := s.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO webauthn_challenges (id, session_data, expires_at, created_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		key, string(data), expiresAt); err != nil {
		s.logger.Warn("webauthn challenge: db insert failed; challenge will not be stored",
			"key", key, "error", err)
	}
}

// pop retrieves and deletes a challenge row in a single transaction to ensure
// true single-use semantics under concurrent access.
func (s *SQLiteChallengeStore) pop(ctx context.Context, key string) (gowebauthn.SessionData, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck — rollback on non-commit paths is intentional

	var sessionDataJSON string
	var expiresAt time.Time

	err = tx.QueryRowContext(ctx,
		`SELECT session_data, expires_at FROM webauthn_challenges WHERE id = ?`, key).
		Scan(&sessionDataJSON, &expiresAt)
	if err == sql.ErrNoRows {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: %w", ErrChallengeNotFound)
	}
	if err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: query: %w", err)
	}

	// Delete the record inside the same transaction — single-use semantics.
	if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE id = ?`, key); err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: delete: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("webauthn challenge: commit: %w", err)
	}

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
