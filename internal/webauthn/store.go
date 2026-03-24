package webauthn

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SQLiteCredentialStore implements CredentialStore using a SQLite database.
type SQLiteCredentialStore struct {
	db *sql.DB
}

// NewSQLiteCredentialStore creates a new SQLiteCredentialStore backed by the given database connection.
func NewSQLiteCredentialStore(db *sql.DB) *SQLiteCredentialStore {
	return &SQLiteCredentialStore{db: db}
}

// Create inserts a new WebAuthn credential into the database.
func (s *SQLiteCredentialStore) Create(ctx context.Context, cred *Credential) error {
	const query = `
		INSERT INTO webauthn_credentials (id, user_id, name, public_key, sign_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	now := time.Now().UTC()
	cred.CreatedAt = now

	_, err := s.db.ExecContext(ctx, query,
		cred.ID, cred.UserID, cred.Name, cred.PublicKey, cred.SignCount, cred.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("webauthn store create: %w", err)
	}
	return nil
}

// GetByID looks up a credential by its base64url-encoded ID.
func (s *SQLiteCredentialStore) GetByID(ctx context.Context, id string) (*Credential, error) {
	const query = `
		SELECT id, user_id, name, public_key, sign_count, created_at, last_used_at
		FROM webauthn_credentials WHERE id = ?`

	row := s.db.QueryRowContext(ctx, query, id)
	cred, err := scanCredential(row)
	if err != nil {
		return nil, fmt.Errorf("webauthn store get by id: %w", err)
	}
	return cred, nil
}

// ListByUser returns all credentials for the given user, ordered by creation time descending.
func (s *SQLiteCredentialStore) ListByUser(ctx context.Context, userID string) ([]*Credential, error) {
	const query = `
		SELECT id, user_id, name, public_key, sign_count, created_at, last_used_at
		FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("webauthn store list by user: %w", err)
	}
	defer rows.Close()

	var creds []*Credential
	for rows.Next() {
		cred, err := scanCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("webauthn store list by user scan: %w", err)
		}
		creds = append(creds, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webauthn store list by user rows: %w", err)
	}
	return creds, nil
}

// CountByUser returns the number of credentials registered for a given user.
func (s *SQLiteCredentialStore) CountByUser(ctx context.Context, userID string) (int, error) {
	const query = `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`
	var count int
	if err := s.db.QueryRowContext(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("webauthn store count by user: %w", err)
	}
	return count, nil
}

// UpdateSignCount updates the sign_count and last_used_at for the given credential.
func (s *SQLiteCredentialStore) UpdateSignCount(ctx context.Context, id string, newCount uint32) error {
	const query = `UPDATE webauthn_credentials SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, newCount, id)
	if err != nil {
		return fmt.Errorf("webauthn store update sign count: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("webauthn store update sign count rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("webauthn store update sign count: %w", ErrCredentialNotFound)
	}
	return nil
}

// Delete removes a credential by its base64url-encoded ID.
func (s *SQLiteCredentialStore) Delete(ctx context.Context, id string) error {
	const query = `DELETE FROM webauthn_credentials WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("webauthn store delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("webauthn store delete rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("webauthn store delete: %w", ErrCredentialNotFound)
	}
	return nil
}

// credScanner is satisfied by both *sql.Row and *sql.Rows.
type credScanner interface {
	Scan(dest ...any) error
}

// scanCredential scans a Credential from a row result.
func scanCredential(s credScanner) (*Credential, error) {
	var cred Credential
	var lastUsedAt sql.NullTime
	err := s.Scan(
		&cred.ID, &cred.UserID, &cred.Name, &cred.PublicKey, &cred.SignCount,
		&cred.CreatedAt, &lastUsedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrCredentialNotFound
		}
		return nil, err
	}
	if lastUsedAt.Valid {
		cred.LastUsedAt = &lastUsedAt.Time
	}
	return &cred, nil
}
