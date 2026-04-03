package user

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// SQLiteStore implements Store and TokenStore using a SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// NewStore creates a new SQLiteStore backed by the given database connection.
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

// Create inserts a new user into the database.
// A new UUID is assigned to user.ID before inserting.
func (s *SQLiteStore) Create(ctx context.Context, u *User) error {
	id, err := newUUID()
	if err != nil {
		return fmt.Errorf("user store create: %w", err)
	}
	u.ID = id

	now := time.Now().UTC()
	u.CreatedAt = now
	u.UpdatedAt = now

	const query = `
		INSERT INTO users (id, username, email, name, password_hash, is_admin, is_active, roles, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		u.ID, u.Username, u.Email, u.Name, u.PasswordHash,
		boolToInt(u.IsAdmin), boolToInt(u.IsActive), u.Roles,
		u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		return mapUserConstraintError(err)
	}
	return nil
}

// GetByID looks up a user by their UUID.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*User, error) {
	const query = `
		SELECT id, username, email, name, password_hash, is_admin, is_active, roles, created_at, updated_at
		FROM users WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, id)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("user store get by id: %w", err)
	}
	return u, nil
}

// GetByUsername looks up a user by their username.
func (s *SQLiteStore) GetByUsername(ctx context.Context, username string) (*User, error) {
	const query = `
		SELECT id, username, email, name, password_hash, is_admin, is_active, roles, created_at, updated_at
		FROM users WHERE username = ?`
	row := s.db.QueryRowContext(ctx, query, username)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("user store get by username: %w", err)
	}
	return u, nil
}

// GetByEmail looks up a user by their email address.
func (s *SQLiteStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	const query = `
		SELECT id, username, email, name, password_hash, is_admin, is_active, roles, created_at, updated_at
		FROM users WHERE email = ?`
	row := s.db.QueryRowContext(ctx, query, email)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("user store get by email: %w", err)
	}
	return u, nil
}

// List returns all users ordered by username.
func (s *SQLiteStore) List(ctx context.Context) ([]*User, error) {
	const query = `
		SELECT id, username, email, name, password_hash, is_admin, is_active, roles, created_at, updated_at
		FROM users ORDER BY username`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("user store list: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("user store list scan: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user store list rows: %w", err)
	}
	return users, nil
}

// Update saves changes to an existing user.
func (s *SQLiteStore) Update(ctx context.Context, u *User) error {
	u.UpdatedAt = time.Now().UTC()

	const query = `
		UPDATE users
		SET username = ?, email = ?, name = ?, password_hash = ?,
		    is_admin = ?, is_active = ?, roles = ?, updated_at = ?
		WHERE id = ?`

	res, err := s.db.ExecContext(ctx, query,
		u.Username, u.Email, u.Name, u.PasswordHash,
		boolToInt(u.IsAdmin), boolToInt(u.IsActive), u.Roles, u.UpdatedAt,
		u.ID,
	)
	if err != nil {
		return fmt.Errorf("user store update: %w", mapUserConstraintError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("user store update rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("user store update: %w", ErrNotFound)
	}
	return nil
}

// Delete removes a user by ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	const query = `DELETE FROM users WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("user store delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("user store delete rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("user store delete: %w", ErrNotFound)
	}
	return nil
}

// HasAdmin returns true if at least one admin user exists in the database.
func (s *SQLiteStore) HasAdmin(ctx context.Context) (bool, error) {
	const query = `SELECT COUNT(*) FROM users WHERE is_admin = 1`
	var count int
	if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return false, fmt.Errorf("user store has admin: %w", err)
	}
	return count > 0, nil
}

// CreateResetToken generates a 32-byte token using crypto/rand, stores it
// with a 1-hour expiry, and returns the hex-encoded token string.
func (s *SQLiteStore) CreateResetToken(ctx context.Context, userID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate reset token: %w", err)
	}
	token := hex.EncodeToString(b)
	expiresAt := time.Now().UTC().Add(1 * time.Hour)
	createdAt := time.Now().UTC()

	const query = `
		INSERT INTO password_reset_tokens (token, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, token, userID, expiresAt, createdAt); err != nil {
		return "", fmt.Errorf("store reset token: %w", err)
	}
	return token, nil
}

// GetResetToken looks up a password reset token.
func (s *SQLiteStore) GetResetToken(ctx context.Context, token string) (*ResetToken, error) {
	const query = `
		SELECT token, user_id, expires_at, used_at, created_at
		FROM password_reset_tokens WHERE token = ?`
	row := s.db.QueryRowContext(ctx, query, token)

	var rt ResetToken
	var usedAt sql.NullTime
	err := row.Scan(&rt.Token, &rt.UserID, &rt.ExpiresAt, &usedAt, &rt.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("get reset token: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get reset token: %w", err)
	}
	if usedAt.Valid {
		rt.UsedAt = &usedAt.Time
	}
	return &rt, nil
}

// MarkResetTokenUsed marks a reset token as used by setting its used_at timestamp.
func (s *SQLiteStore) MarkResetTokenUsed(ctx context.Context, token string) error {
	const query = `UPDATE password_reset_tokens SET used_at = ? WHERE token = ?`
	res, err := s.db.ExecContext(ctx, query, time.Now().UTC(), token)
	if err != nil {
		return fmt.Errorf("mark reset token used: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark reset token used rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("mark reset token used: %w", ErrNotFound)
	}
	return nil
}

// CreateMagicLinkToken generates a 32-byte token using crypto/rand, stores it
// with the specified TTL, and returns the full MagicLinkToken.
func (s *SQLiteStore) CreateMagicLinkToken(ctx context.Context, userID string, ttlMinutes int) (*MagicLinkToken, error) {
	if ttlMinutes <= 0 {
		ttlMinutes = 15
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate magic link token: %w", err)
	}
	token := hex.EncodeToString(b)

	interval := fmt.Sprintf("+%d minutes", ttlMinutes)
	const insertQuery = `
		INSERT INTO magic_link_tokens (token, user_id, expires_at)
		VALUES (?, ?, datetime('now', ?))`
	if _, err := s.db.ExecContext(ctx, insertQuery, token, userID, interval); err != nil {
		return nil, fmt.Errorf("store magic link token: %w", err)
	}

	const selectQuery = `
		SELECT token, user_id, expires_at, used_at, created_at
		FROM magic_link_tokens WHERE token = ?`
	row := s.db.QueryRowContext(ctx, selectQuery, token)
	var mlt MagicLinkToken
	var usedAt sql.NullTime
	if err := row.Scan(&mlt.Token, &mlt.UserID, &mlt.ExpiresAt, &usedAt, &mlt.CreatedAt); err != nil {
		return nil, fmt.Errorf("fetch magic link token after insert: %w", err)
	}
	if usedAt.Valid {
		mlt.UsedAt = &usedAt.Time
	}
	return &mlt, nil
}

// GetMagicLinkToken looks up a magic link token by its token string.
func (s *SQLiteStore) GetMagicLinkToken(ctx context.Context, token string) (*MagicLinkToken, error) {
	const query = `
		SELECT token, user_id, expires_at, used_at, created_at
		FROM magic_link_tokens WHERE token = ?`
	row := s.db.QueryRowContext(ctx, query, token)
	var mlt MagicLinkToken
	var usedAt sql.NullTime
	err := row.Scan(&mlt.Token, &mlt.UserID, &mlt.ExpiresAt, &usedAt, &mlt.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrMagicLinkTokenNotFound
		}
		return nil, fmt.Errorf("get magic link token: %w", err)
	}
	if usedAt.Valid {
		mlt.UsedAt = &usedAt.Time
	}
	return &mlt, nil
}

// MarkMagicLinkTokenUsed atomically marks a magic link token as used.
// Returns ErrMagicLinkTokenUsed if the token was already used (double-spend protection).
func (s *SQLiteStore) MarkMagicLinkTokenUsed(ctx context.Context, token string) error {
	const query = `UPDATE magic_link_tokens SET used_at = datetime('now') WHERE token = ? AND used_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("mark magic link token used: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark magic link token used rows affected: %w", err)
	}
	if n == 0 {
		return ErrMagicLinkTokenUsed
	}
	return nil
}

// DeleteExpiredMagicLinkTokens removes all expired or already-used magic link tokens.
func (s *SQLiteStore) DeleteExpiredMagicLinkTokens(ctx context.Context) error {
	const query = `DELETE FROM magic_link_tokens WHERE expires_at < datetime('now') OR used_at IS NOT NULL`
	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("delete expired magic link tokens: %w", err)
	}
	return nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// scanUser scans a user from a row result.
func scanUser(s scanner) (*User, error) {
	var u User
	var isAdmin, isActive int
	var passwordHash sql.NullString
	err := s.Scan(
		&u.ID, &u.Username, &u.Email, &u.Name, &passwordHash,
		&isAdmin, &isActive, &u.Roles, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.IsActive = isActive != 0
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	return &u, nil
}

// boolToInt converts a bool to a SQLite-friendly integer (0 or 1).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// mapUserConstraintError maps UNIQUE constraint failures to typed sentinel errors.
func mapUserConstraintError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") {
		if strings.Contains(msg, "users.username") {
			return ErrUsernameTaken
		}
		if strings.Contains(msg, "users.email") {
			return ErrEmailTaken
		}
	}
	return err
}
