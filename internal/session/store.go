package session

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// sessionColumns lists the session columns in scanSession order. Keep the two
// in sync; SELECTs should use this list rather than repeating it.
const sessionColumns = `id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at, last_used_at`

// SQLiteStore implements Store using a SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// NewStore creates a new SQLiteStore backed by the given database connection.
func NewStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// Create inserts a new session into the database. If PublicID is empty, a
// random one is generated and written back to the struct. If LastUsedAt is
// zero it is set to CreatedAt so the idle window starts at creation.
func (s *SQLiteStore) Create(ctx context.Context, sess *Session) error {
	if sess.PublicID == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("session store create: generate public id: %w", err)
		}
		sess.PublicID = hex.EncodeToString(b)
	}
	if sess.LastUsedAt.IsZero() {
		sess.LastUsedAt = sess.CreatedAt
	}
	const query = `
		INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		sess.ID, sess.PublicID, sess.UserID, sess.AppID,
		sess.IPAddress, sess.UserAgent,
		sess.ExpiresAt, sess.CreatedAt, sess.LastUsedAt,
	)
	if err != nil {
		return fmt.Errorf("session store create: %w", err)
	}
	return nil
}

// GetByID looks up a session by its token ID.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions WHERE id = ?`

	row := s.db.QueryRowContext(ctx, query, id)
	sess, err := scanSession(row)
	if err != nil {
		return nil, fmt.Errorf("session store get by id: %w", err)
	}
	return sess, nil
}

// ListByUser returns all sessions for a given user, ordered by creation time descending.
func (s *SQLiteStore) ListByUser(ctx context.Context, userID string) ([]*Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions WHERE user_id = ? ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("session store list by user: %w", err)
	}
	defer rows.Close()
	return scanSessions(rows, "list by user")
}

// ListAll returns all non-expired sessions ordered by creation time descending.
func (s *SQLiteStore) ListAll(ctx context.Context) ([]*Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions WHERE expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("session store list all: %w", err)
	}
	defer rows.Close()
	return scanSessions(rows, "list all")
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

// CountActive returns the number of sessions that have not passed their
// absolute expiry. It is a single COUNT query used by the metrics endpoint; the
// idle window is not applied (it expires a session on read, not in the table).
func (s *SQLiteStore) CountActive(ctx context.Context) (int, error) {
	const query = `SELECT COUNT(*) FROM sessions WHERE expires_at > ?`

	var n int
	if err := s.db.QueryRowContext(ctx, query, time.Now().UTC()).Scan(&n); err != nil {
		return 0, fmt.Errorf("session store count active: %w", err)
	}
	return n, nil
}

// TouchLastUsed records that a session was used, but only when the stored
// value is older than staleBefore. The conditional WHERE is the throttle: two
// concurrent requests for the same session produce a single write. Sessions
// written before the last_used_at migration (NULL) are updated too.
func (s *SQLiteStore) TouchLastUsed(ctx context.Context, id string, now, staleBefore time.Time) error {
	const query = `
		UPDATE sessions SET last_used_at = ?
		WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`
	if _, err := s.db.ExecContext(ctx, query, now, id, staleBefore); err != nil {
		return fmt.Errorf("session store touch last used: %w", err)
	}
	return nil
}

// DeleteIdleBefore removes sessions whose last use is before cutoff.
// Rows with a NULL last_used_at (written before migration 018) are compared on
// created_at, matching how the service evaluates the idle window.
func (s *SQLiteStore) DeleteIdleBefore(ctx context.Context, cutoff time.Time) error {
	const query = `DELETE FROM sessions WHERE COALESCE(last_used_at, created_at) < ?`
	if _, err := s.db.ExecContext(ctx, query, cutoff); err != nil {
		return fmt.Errorf("session store delete idle: %w", err)
	}
	return nil
}

// sessionScanner is satisfied by both *sql.Row and *sql.Rows.
type sessionScanner interface {
	Scan(dest ...any) error
}

// scanSessions drains rows into a slice of sessions.
func scanSessions(rows *sql.Rows, op string) ([]*Session, error) {
	var sessions []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("session store %s scan: %w", op, err)
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session store %s rows: %w", op, err)
	}
	return sessions, nil
}

// scanSession scans a session from a row result.
func scanSession(s sessionScanner) (*Session, error) {
	var sess Session
	var appID sql.NullString
	var lastUsedAt sql.NullTime
	err := s.Scan(
		&sess.ID, &sess.PublicID, &sess.UserID, &appID,
		&sess.IPAddress, &sess.UserAgent,
		&sess.ExpiresAt, &sess.CreatedAt, &lastUsedAt,
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
	if lastUsedAt.Valid {
		sess.LastUsedAt = lastUsedAt.Time
	}
	return &sess, nil
}
