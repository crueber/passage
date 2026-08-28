package session

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// SQLiteStore implements Store using a SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// NewStore creates a new SQLiteStore backed by the given database connection.
func NewStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// Create inserts a new session into the database. If PublicID is empty, a
// random one is generated and written back to the struct.
func (s *SQLiteStore) Create(ctx context.Context, sess *Session) error {
	if sess.PublicID == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("session store create: generate public id: %w", err)
		}
		sess.PublicID = hex.EncodeToString(b)
	}
	const query = `
		INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		sess.ID, sess.PublicID, sess.UserID, sess.AppID,
		sess.IPAddress, sess.UserAgent,
		sess.ExpiresAt, sess.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("session store create: %w", err)
	}
	return nil
}

// GetByID looks up a session by its token ID.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*Session, error) {
	const query = `
		SELECT id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at
		FROM sessions WHERE id = ?`

	row := s.db.QueryRowContext(ctx, query, id)
	sess, err := scanSession(row)
	if err != nil {
		return nil, fmt.Errorf("session store get by id: %w", err)
	}
	return sess, nil
}

// ListByUser returns all sessions for a given user, ordered by creation time descending.
func (s *SQLiteStore) ListByUser(ctx context.Context, userID string) ([]*Session, error) {
	const query = `
		SELECT id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at
		FROM sessions WHERE user_id = ? ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("session store list by user: %w", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("session store list by user scan: %w", err)
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session store list by user rows: %w", err)
	}
	return sessions, nil
}

// ListAll returns all non-expired sessions ordered by creation time descending.
func (s *SQLiteStore) ListAll(ctx context.Context) ([]*Session, error) {
	const query = `
		SELECT id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at
		FROM sessions WHERE expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("session store list all: %w", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("session store list all scan: %w", err)
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session store list all rows: %w", err)
	}
	return sessions, nil
}

// Delete removes a session by its token ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	const query = `DELETE FROM sessions WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("session store delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("session store delete rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("session store delete: %w", ErrSessionNotFound)
	}
	return nil
}

// DeleteByPublicID removes a session by its public (non-secret) identifier.
// Used by the admin revoke endpoint so bearer tokens never appear in URLs.
func (s *SQLiteStore) DeleteByPublicID(ctx context.Context, publicID string) error {
	const query = `DELETE FROM sessions WHERE public_id = ?`
	res, err := s.db.ExecContext(ctx, query, publicID)
	if err != nil {
		return fmt.Errorf("session store delete by public id: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("session store delete by public id rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("session store delete by public id: %w", ErrSessionNotFound)
	}
	return nil
}

// DeleteByUser removes all sessions for the given user ID.
func (s *SQLiteStore) DeleteByUser(ctx context.Context, userID string) error {
	const query = `DELETE FROM sessions WHERE user_id = ?`
	if _, err := s.db.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("session store delete by user: %w", err)
	}
	return nil
}

// DeleteExpired removes all sessions whose expiry time is in the past.
func (s *SQLiteStore) DeleteExpired(ctx context.Context) error {
	const query = `DELETE FROM sessions WHERE expires_at < ?`
	if _, err := s.db.ExecContext(ctx, query, time.Now().UTC()); err != nil {
		return fmt.Errorf("session store delete expired: %w", err)
	}
	return nil
}

// sessionScanner is satisfied by both *sql.Row and *sql.Rows.
type sessionScanner interface {
	Scan(dest ...any) error
}

// scanSession scans a session from a row result.
func scanSession(s sessionScanner) (*Session, error) {
	var sess Session
	var appID sql.NullString
	err := s.Scan(
		&sess.ID, &sess.PublicID, &sess.UserID, &appID,
		&sess.IPAddress, &sess.UserAgent,
		&sess.ExpiresAt, &sess.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	if appID.Valid {
		sess.AppID = &appID.String
	}
	return &sess, nil
}
