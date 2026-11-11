package adminapi

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Store is the persistence interface for API tokens. It is defined here, at
// the consumer boundary, as per Go convention.
type Store interface {
	// Create inserts a token. ID and CreatedAt are filled in when zero.
	Create(ctx context.Context, t *Token) error
	// List returns every token, newest first, revoked ones included.
	List(ctx context.Context) ([]*Token, error)
	// GetByHash looks a token up by its SHA-256 hex digest.
	GetByHash(ctx context.Context, hash string) (*Token, error)
	// GetByID looks a token up by its ID. Used by the admin UI.
	GetByID(ctx context.Context, id string) (*Token, error)
	// Revoke stamps revoked_at. Returns ErrTokenNotFound for a missing ID.
	Revoke(ctx context.Context, id string, at time.Time) error
	// TouchLastUsed records a successful use.
	TouchLastUsed(ctx context.Context, id string, at time.Time) error
}

// tokenColumns lists the api_tokens columns in scan order. Keep the two in
// sync; SELECTs use this list rather than repeating it.
const tokenColumns = `id, name, token_hash, created_at, last_used_at, revoked_at`

// SQLiteStore implements Store using a SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// NewStore creates a new SQLiteStore backed by the given database.
func NewStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// newUUID generates a random UUID v4 using crypto/rand.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	// Set version 4 bits.
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits.
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Create inserts a token row, assigning ID and CreatedAt when they are zero.
func (s *SQLiteStore) Create(ctx context.Context, t *Token) error {
	if t == nil {
		return errors.New("adminapi store create: nil token")
	}
	if t.ID == "" {
		id, err := newUUID()
		if err != nil {
			return fmt.Errorf("adminapi store create: %w", err)
		}
		t.ID = id
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}

	const query = `
		INSERT INTO api_tokens (id, name, token_hash, created_at)
		VALUES (?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, t.ID, t.Name, t.TokenHash, t.CreatedAt); err != nil {
		return fmt.Errorf("adminapi store create: %w", err)
	}
	return nil
}

// List returns every token, newest first.
func (s *SQLiteStore) List(ctx context.Context) ([]*Token, error) {
	query := `SELECT ` + tokenColumns + ` FROM api_tokens ORDER BY created_at DESC, id`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("adminapi store list: %w", err)
	}
	defer rows.Close()

	var tokens []*Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("adminapi store list scan: %w", err)
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("adminapi store list rows: %w", err)
	}
	return tokens, nil
}

// GetByHash returns the token with the given hash.
func (s *SQLiteStore) GetByHash(ctx context.Context, hash string) (*Token, error) {
	query := `SELECT ` + tokenColumns + ` FROM api_tokens WHERE token_hash = ?`
	t, err := scanToken(s.db.QueryRowContext(ctx, query, hash))
	if err != nil {
		return nil, fmt.Errorf("adminapi store get by hash: %w", err)
	}
	return t, nil
}

// GetByID returns the token with the given ID.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*Token, error) {
	query := `SELECT ` + tokenColumns + ` FROM api_tokens WHERE id = ?`
	t, err := scanToken(s.db.QueryRowContext(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("adminapi store get by id: %w", err)
	}
	return t, nil
}

// Revoke stamps the revocation time on a token.
func (s *SQLiteStore) Revoke(ctx context.Context, id string, at time.Time) error {
	const query = `UPDATE api_tokens SET revoked_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, at, id)
	if err != nil {
		return fmt.Errorf("adminapi store revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("adminapi store revoke rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("adminapi store revoke: %w", ErrTokenNotFound)
	}
	return nil
}

// TouchLastUsed records a successful use of a token.
func (s *SQLiteStore) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	const query = `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, at, id)
	if err != nil {
		return fmt.Errorf("adminapi store touch last used: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("adminapi store touch last used rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("adminapi store touch last used: %w", ErrTokenNotFound)
	}
	return nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanToken reads one token row, mapping sql.ErrNoRows to ErrTokenNotFound.
func scanToken(row rowScanner) (*Token, error) {
	var (
		t         Token
		lastUsed  sql.NullTime
		revokedAt sql.NullTime
	)
	if err := row.Scan(&t.ID, &t.Name, &t.TokenHash, &t.CreatedAt, &lastUsed, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	if lastUsed.Valid {
		t.LastUsedAt = lastUsed.Time
	}
	if revokedAt.Valid {
		t.RevokedAt = revokedAt.Time
	}
	return &t, nil
}
