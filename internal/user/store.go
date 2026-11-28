package user

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const userColumns = `id, username, email, name, password_hash, is_admin, is_active, roles, email_verified, theme, app_view, created_at, updated_at`

// requireRows turns a zero-rows-affected SQL result into zeroErr.
func requireRows(res sql.Result, op string, zeroErr error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows affected: %w", op, err)
	}
	if n == 0 {
		return fmt.Errorf("%s: %w", op, zeroErr)
	}
	return nil
}

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
		INSERT INTO users (id, username, email, name, password_hash, is_admin, is_active, roles, email_verified, theme, app_view, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		u.ID, u.Username, u.Email, u.Name, u.PasswordHash,
		boolToInt(u.IsAdmin), boolToInt(u.IsActive), u.Roles,
		boolToInt(u.EmailVerified), u.Theme, u.AppView,
		u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		return mapUserConstraintError(err)
	}
	return nil
}

// GetByID looks up a user by their UUID.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, id)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("user store get by id: %w", err)
	}
	return u, nil
}

// GetByUsername looks up a user by their username.
func (s *SQLiteStore) GetByUsername(ctx context.Context, username string) (*User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE username = ?`
	row := s.db.QueryRowContext(ctx, query, username)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("user store get by username: %w", err)
	}
	return u, nil
}

// GetByEmail looks up a user by their email address case-insensitively so
// legacy mixed-case rows remain reachable alongside lowercased lookups.
func (s *SQLiteStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE LOWER(email) = LOWER(?)`
	row := s.db.QueryRowContext(ctx, query, strings.TrimSpace(email))
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("user store get by email: %w", err)
	}
	return u, nil
}

// List returns all users ordered by username.
func (s *SQLiteStore) List(ctx context.Context) ([]*User, error) {
	const query = `SELECT ` + userColumns + ` FROM users ORDER BY username`
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

// Count returns the number of user accounts, including inactive ones. It is a
// single COUNT query used by the metrics endpoint.
func (s *SQLiteStore) Count(ctx context.Context) (int, error) {
	const query = `SELECT COUNT(*) FROM users`

	var n int
	if err := s.db.QueryRowContext(ctx, query).Scan(&n); err != nil {
		return 0, fmt.Errorf("user store count: %w", err)
	}
	return n, nil
}

// Update saves changes to an existing user.
func (s *SQLiteStore) Update(ctx context.Context, u *User) error {
	u.UpdatedAt = time.Now().UTC()

	const query = `
		UPDATE users
		SET username = ?, email = ?, name = ?, password_hash = ?,
		    is_admin = ?, is_active = ?, roles = ?, email_verified = ?, theme = ?, app_view = ?, updated_at = ?
		WHERE id = ?`

	res, err := s.db.ExecContext(ctx, query,
		u.Username, u.Email, u.Name, u.PasswordHash,
		boolToInt(u.IsAdmin), boolToInt(u.IsActive), u.Roles, boolToInt(u.EmailVerified), u.Theme, u.AppView, u.UpdatedAt,
		u.ID,
	)
	if err != nil {
		return fmt.Errorf("user store update: %w", mapUserConstraintError(err))
	}
	return requireRows(res, "user store update", ErrNotFound)
}

// SetEmailVerified sets only the email_verified flag for the given user.
func (s *SQLiteStore) SetEmailVerified(ctx context.Context, id string, verified bool) error {
	const query = `UPDATE users SET email_verified = ?, updated_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, boolToInt(verified), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("user store set email verified: %w", err)
	}
	return requireRows(res, "user store set email verified", ErrNotFound)
}

// SetName sets only the display name for the given user.
func (s *SQLiteStore) SetName(ctx context.Context, id, name string) error {
	const query = `UPDATE users SET name = ?, updated_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, name, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("user store set name: %w", err)
	}
	return requireRows(res, "user store set name", ErrNotFound)
}

// SetTheme sets only the colour-theme override for the given user. An empty
// value means "follow the server default".
func (s *SQLiteStore) SetTheme(ctx context.Context, id, themeName string) error {
	const query = `UPDATE users SET theme = ?, updated_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, themeName, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("user store set theme: %w", err)
	}
	return requireRows(res, "user store set theme", ErrNotFound)
}

// SetAppView sets only the My Apps default view for the given user. An empty
// value means Comfortable.
func (s *SQLiteStore) SetAppView(ctx context.Context, id, view string) error {
	const query = `UPDATE users SET app_view = ?, updated_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, view, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("user store set app view: %w", err)
	}
	return requireRows(res, "user store set app view", ErrNotFound)
}

// SetPasswordHash updates only password_hash and updated_at so a password
// change cannot overwrite concurrent admin edits to other user fields.
func (s *SQLiteStore) SetPasswordHash(ctx context.Context, id, hash string) error {
	const query = `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, hash, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("user store set password hash: %w", err)
	}
	return requireRows(res, "user store set password hash", ErrNotFound)
}

// UpdateProfile atomically writes display name, theme, and app view in one
// statement so a partial failure cannot leave half-saved profile edits.
func (s *SQLiteStore) UpdateProfile(ctx context.Context, id, name, themeName, appView string) error {
	const query = `UPDATE users SET name = ?, theme = ?, app_view = ?, updated_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, name, themeName, appView, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("user store update profile: %w", err)
	}
	return requireRows(res, "user store update profile", ErrNotFound)
}

// Delete removes a user by ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	const query = `DELETE FROM users WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("user store delete: %w", err)
	}
	return requireRows(res, "user store delete", ErrNotFound)
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

// MarkResetTokenUsed atomically marks an unused, unexpired reset token as used.
// Returns ErrTokenUsed if another request already consumed it.
func (s *SQLiteStore) MarkResetTokenUsed(ctx context.Context, token string) error {
	now := time.Now().UTC()
	const query = `UPDATE password_reset_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL AND expires_at > ?`
	res, err := s.db.ExecContext(ctx, query, now, token, now)
	if err != nil {
		return fmt.Errorf("mark reset token used: %w", err)
	}
	return requireRows(res, "mark reset token used", ErrTokenUsed)
}

// DeleteExpiredResetTokens removes expired or already-used password reset tokens.
// DeleteExpiredResetTokens removes expired or already-used password reset tokens.
// Split into two statements so SQLite can use the expires_at index and the
// partial used_at index instead of falling back to a full table scan on OR.
func (s *SQLiteStore) DeleteExpiredResetTokens(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE expires_at < ?`, time.Now().UTC()); err != nil {
		return fmt.Errorf("delete expired reset tokens: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE used_at IS NOT NULL`); err != nil {
		return fmt.Errorf("delete used reset tokens: %w", err)
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
	now := time.Now().UTC()
	mlt := &MagicLinkToken{
		Token:     hex.EncodeToString(b),
		UserID:    userID,
		ExpiresAt: now.Add(time.Duration(ttlMinutes) * time.Minute),
		CreatedAt: now,
	}

	const insertQuery = `
		INSERT INTO magic_link_tokens (token, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, insertQuery, mlt.Token, mlt.UserID, mlt.ExpiresAt, mlt.CreatedAt); err != nil {
		return nil, fmt.Errorf("store magic link token: %w", err)
	}
	return mlt, nil
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
		if errors.Is(err, sql.ErrNoRows) {
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
	const query = `UPDATE magic_link_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, time.Now().UTC(), token)
	if err != nil {
		return fmt.Errorf("mark magic link token used: %w", err)
	}
	return requireRows(res, "mark magic link token used", ErrMagicLinkTokenUsed)
}

// DeleteExpiredMagicLinkTokens removes all expired or already-used magic link tokens.
func (s *SQLiteStore) DeleteExpiredMagicLinkTokens(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM magic_link_tokens WHERE expires_at < ?`, time.Now().UTC()); err != nil {
		return fmt.Errorf("delete expired magic link tokens: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM magic_link_tokens WHERE used_at IS NOT NULL`); err != nil {
		return fmt.Errorf("delete used magic link tokens: %w", err)
	}
	return nil
}

// CreateEmailVerificationToken generates a 32-byte hex token, invalidates any
// earlier unused token for the same user, and stores the new one with the given
// TTL. Only the newest link can verify an address. The delete and insert share
// a transaction so two concurrent resends cannot leave two live links.
func (s *SQLiteStore) CreateEmailVerificationToken(ctx context.Context, userID, emailAddr string, ttl time.Duration) (*EmailVerificationToken, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate email verification token: %w", err)
	}

	now := time.Now().UTC()
	evt := &EmailVerificationToken{
		Token:     hex.EncodeToString(b),
		UserID:    userID,
		Email:     emailAddr,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store email verification token begin: %w", err)
	}
	// Rollback after a successful commit is a no-op; the error is deliberately
	// ignored so it cannot mask the real result.
	defer func() { _ = tx.Rollback() }()

	const deleteQuery = `DELETE FROM email_verification_tokens WHERE user_id = ? AND used_at IS NULL`
	if _, err := tx.ExecContext(ctx, deleteQuery, userID); err != nil {
		return nil, fmt.Errorf("store email verification token invalidate previous: %w", err)
	}

	const insertQuery = `
		INSERT INTO email_verification_tokens (token, user_id, email, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`
	if _, err := tx.ExecContext(ctx, insertQuery, evt.Token, evt.UserID, evt.Email, evt.ExpiresAt, evt.CreatedAt); err != nil {
		return nil, fmt.Errorf("store email verification token insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store email verification token commit: %w", err)
	}
	return evt, nil
}

// GetEmailVerificationToken looks up an email verification token.
func (s *SQLiteStore) GetEmailVerificationToken(ctx context.Context, token string) (*EmailVerificationToken, error) {
	const query = `
		SELECT token, user_id, email, expires_at, used_at, created_at
		FROM email_verification_tokens WHERE token = ?`
	row := s.db.QueryRowContext(ctx, query, token)

	var evt EmailVerificationToken
	var usedAt sql.NullTime
	err := row.Scan(&evt.Token, &evt.UserID, &evt.Email, &evt.ExpiresAt, &usedAt, &evt.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrEmailVerificationTokenNotFound
		}
		return nil, fmt.Errorf("get email verification token: %w", err)
	}
	if usedAt.Valid {
		evt.UsedAt = &usedAt.Time
	}
	return &evt, nil
}

// MarkEmailVerificationTokenUsed atomically marks a token as used.
// Returns ErrEmailVerificationTokenUsed if it was already consumed, which closes
// the double-spend window between two concurrent clicks.
func (s *SQLiteStore) MarkEmailVerificationTokenUsed(ctx context.Context, token string) error {
	const query = `UPDATE email_verification_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, time.Now().UTC(), token)
	if err != nil {
		return fmt.Errorf("mark email verification token used: %w", err)
	}
	return requireRows(res, "mark email verification token used", ErrEmailVerificationTokenUsed)
}

// DeleteExpiredEmailVerificationTokens removes expired or consumed verification tokens.
func (s *SQLiteStore) DeleteExpiredEmailVerificationTokens(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM email_verification_tokens WHERE expires_at < ?`, time.Now().UTC()); err != nil {
		return fmt.Errorf("delete expired email verification tokens: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM email_verification_tokens WHERE used_at IS NOT NULL`); err != nil {
		return fmt.Errorf("delete used email verification tokens: %w", err)
	}
	return nil
}

// CreateInvitation stores a new invitation and invalidates any earlier pending
// one for the same address. The token is 32 bytes from crypto/rand; the delete
// and insert share a transaction so two concurrent invites cannot leave two
// live links for one address (the partial unique index is the backstop).
func (s *SQLiteStore) CreateInvitation(ctx context.Context, emailAddr, name, invitedBy string, ttl time.Duration) (*Invitation, error) {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate invitation token: %w", err)
	}

	id, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("generate invitation id: %w", err)
	}

	now := time.Now().UTC()
	inv := &Invitation{
		ID:        id,
		Token:     hex.EncodeToString(b),
		Email:     emailAddr,
		Name:      name,
		InvitedBy: invitedBy,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store invitation begin: %w", err)
	}
	// Rollback after a successful commit is a no-op; the error is deliberately
	// ignored so it cannot mask the real result.
	defer func() { _ = tx.Rollback() }()

	const deleteQuery = `DELETE FROM invitations WHERE email = ? AND accepted_at IS NULL`
	if _, err := tx.ExecContext(ctx, deleteQuery, emailAddr); err != nil {
		return nil, fmt.Errorf("store invitation invalidate previous: %w", err)
	}

	const insertQuery = `
		INSERT INTO invitations (id, token, email, name, invited_by, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if _, err := tx.ExecContext(ctx, insertQuery,
		inv.ID, inv.Token, inv.Email, inv.Name, inv.InvitedBy, inv.ExpiresAt, inv.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("store invitation insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store invitation commit: %w", err)
	}
	return inv, nil
}

// GetInvitation looks up an invitation by its emailed token.
func (s *SQLiteStore) GetInvitation(ctx context.Context, token string) (*Invitation, error) {
	const query = `
		SELECT id, token, email, name, invited_by, expires_at, accepted_at, created_at
		FROM invitations WHERE token = ?`
	row := s.db.QueryRowContext(ctx, query, token)
	inv, err := scanInvitation(row)
	if err != nil {
		return nil, fmt.Errorf("get invitation: %w", err)
	}
	return inv, nil
}

// MarkInvitationAccepted atomically consumes an invitation. A token that is
// already consumed (or has vanished) changes no rows, which closes the
// double-accept window between two concurrent clicks.
func (s *SQLiteStore) MarkInvitationAccepted(ctx context.Context, token string) error {
	const query = `UPDATE invitations SET accepted_at = ? WHERE token = ? AND accepted_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, time.Now().UTC(), token)
	if err != nil {
		return fmt.Errorf("mark invitation accepted: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark invitation accepted rows affected: %w", err)
	}
	if n == 0 {
		return ErrInvitationAccepted
	}
	return nil
}

// DeleteInvitation removes one still-pending invitation by ID. A consumed
// invitation is never deleted this way: it is the record that the address was
// once invited, and deleting it would not undo the account.
func (s *SQLiteStore) DeleteInvitation(ctx context.Context, id string) error {
	const query = `DELETE FROM invitations WHERE id = ? AND accepted_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete invitation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete invitation rows affected: %w", err)
	}
	if n == 0 {
		return ErrInvitationNotFound
	}
	return nil
}

// ListPendingInvitations returns unaccepted, unexpired invitations, newest
// first. Expired rows are excluded so the admin list only shows links that can
// still be used.
func (s *SQLiteStore) ListPendingInvitations(ctx context.Context) ([]*Invitation, error) {
	const query = `
		SELECT id, token, email, name, invited_by, expires_at, accepted_at, created_at
		FROM invitations
		WHERE accepted_at IS NULL AND expires_at > ?
		ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("list pending invitations: %w", err)
	}
	defer rows.Close()

	var invitations []*Invitation
	for rows.Next() {
		inv, err := scanInvitation(rows)
		if err != nil {
			return nil, fmt.Errorf("list pending invitations scan: %w", err)
		}
		invitations = append(invitations, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list pending invitations rows: %w", err)
	}
	return invitations, nil
}

// DeleteExpiredInvitations removes invitations that expired before they were
// accepted. Consumed rows are kept: they are the only record that an address
// was invited, and they are tiny.
func (s *SQLiteStore) DeleteExpiredInvitations(ctx context.Context) error {
	const query = `DELETE FROM invitations WHERE accepted_at IS NULL AND expires_at < ?`
	if _, err := s.db.ExecContext(ctx, query, time.Now().UTC()); err != nil {
		return fmt.Errorf("delete expired invitations: %w", err)
	}
	return nil
}

// scanInvitation scans an invitation from a row result.
func scanInvitation(s scanner) (*Invitation, error) {
	var inv Invitation
	var acceptedAt sql.NullTime
	err := s.Scan(
		&inv.ID, &inv.Token, &inv.Email, &inv.Name, &inv.InvitedBy,
		&inv.ExpiresAt, &acceptedAt, &inv.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvitationNotFound
		}
		return nil, err
	}
	if acceptedAt.Valid {
		inv.AcceptedAt = &acceptedAt.Time
	}
	return &inv, nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// scanUser scans a user from a row result.
func scanUser(s scanner) (*User, error) {
	var u User
	var isAdmin, isActive, emailVerified int
	var passwordHash sql.NullString
	err := s.Scan(
		&u.ID, &u.Username, &u.Email, &u.Name, &passwordHash,
		&isAdmin, &isActive, &u.Roles, &emailVerified, &u.Theme, &u.AppView, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.IsActive = isActive != 0
	u.EmailVerified = emailVerified != 0
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
