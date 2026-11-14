package mfa

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Sentinel errors returned by the store and service.
var (
	// ErrNotFound means the user has no MFA record (or no live challenge).
	ErrNotFound = errors.New("mfa: not found")
	// ErrNotPending means an enrollment row exists but is already enabled, so
	// a pending-secret write would clobber a working second factor.
	ErrNotPending = errors.New("mfa: enrollment is not pending")
	// ErrChallengeExpired means the pending challenge is past its expiry.
	ErrChallengeExpired = errors.New("mfa: challenge expired")
	// ErrReplay means the presented factor was already used: a TOTP step at or
	// below last_step, or a recovery code with used_at set.
	ErrReplay = errors.New("mfa: code already used")
	// ErrInvalidCode means the code did not match.
	ErrInvalidCode = errors.New("mfa: invalid code")
	// ErrNotEnabled means the user has not completed enrollment.
	ErrNotEnabled = errors.New("mfa: not enabled")
)

// Credential is a user's TOTP enrollment.
type Credential struct {
	UserID string
	// Secret is the base32 TOTP secret. It is never logged or rendered outside
	// the enrollment page.
	Secret string
	// LastStep is the highest TOTP step accepted so far. It is the anti-replay
	// watermark: codes from that step or earlier are refused.
	LastStep int64
	// EnabledAt is nil while enrollment is pending (secret issued, code not yet
	// verified). Only an enabled credential is enforced at login.
	EnabledAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Challenge is a pending second factor for a password-authenticated user. It is
// not a session: it carries no privileges until a factor is verified.
type Challenge struct {
	Token     string
	UserID    string
	ReturnTo  string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Store persists MFA state. It is a concrete type used by Service; the HTTP
// layer depends on Service, never on the store.
//
// Secrets are encrypted with cipher on every write and decrypted on every read,
// so no caller above this layer sees a stored value. A nil cipher means
// plaintext storage; that exists only for tests and for code that never handles
// a secret.
type Store struct {
	db     *sql.DB
	cipher *Cipher
}

// NewStore creates a Store backed by db. Pass a nil cipher to store secrets in
// plain text (tests only).
func NewStore(db *sql.DB, cipher *Cipher) *Store {
	return &Store{db: db, cipher: cipher}
}

// Get returns the user's MFA row, with the secret decrypted and bound to the
// owning user.
func (s *Store) Get(ctx context.Context, userID string) (*Credential, error) {
	const query = `
		SELECT user_id, secret, last_step, enabled_at, created_at, updated_at
		FROM user_mfa WHERE user_id = ?`
	var c Credential
	var enabledAt sql.NullTime
	err := s.db.QueryRowContext(ctx, query, userID).
		Scan(&c.UserID, &c.Secret, &c.LastStep, &enabledAt, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("mfa store get: %w", err)
	}
	secret, err := s.decryptSecret(userID, c.Secret)
	if err != nil {
		return nil, fmt.Errorf("mfa store get: %w", err)
	}
	c.Secret = secret
	if enabledAt.Valid {
		t := enabledAt.Time
		c.EnabledAt = &t
	}
	return &c, nil
}

// Enabled reports whether the user has completed enrollment.
func (s *Store) Enabled(ctx context.Context, userID string) (bool, error) {
	const query = `SELECT COUNT(*) FROM user_mfa WHERE user_id = ? AND enabled_at IS NOT NULL`
	var n int
	if err := s.db.QueryRowContext(ctx, query, userID).Scan(&n); err != nil {
		return false, fmt.Errorf("mfa store enabled: %w", err)
	}
	return n > 0, nil
}

// UpsertPending stores a fresh pending secret for userID.
//
// The DO UPDATE carries a WHERE guard so an enabled credential is never
// silently replaced: if the user already has a working second factor this is a
// no-op and the caller is told so with ErrNotPending.
func (s *Store) UpsertPending(ctx context.Context, userID, secret string, now time.Time) error {
	stored, err := s.encryptSecret(userID, secret)
	if err != nil {
		return fmt.Errorf("mfa store upsert pending: %w", err)
	}
	const query = `
		INSERT INTO user_mfa (user_id, secret, last_step, enabled_at, created_at, updated_at)
		VALUES (?, ?, 0, NULL, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			secret = excluded.secret,
			last_step = 0,
			updated_at = excluded.updated_at
		WHERE user_mfa.enabled_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, userID, stored, now, now)
	if err != nil {
		return fmt.Errorf("mfa store upsert pending: %w", err)
	}
	// A conflicting row that is already enabled makes the UPDATE a no-op and
	// reports zero rows, which is exactly the case we must refuse.
	if err := requireRows(res, "mfa store upsert pending", ErrNotPending); err != nil {
		return err
	}
	return nil
}

// EnableWithRecoveryCodes flips a pending enrollment to enabled, records the
// accepted TOTP step, and replaces the recovery-code set in one transaction, so
// an enabled factor can never exist without its recovery codes.
func (s *Store) EnableWithRecoveryCodes(ctx context.Context, userID string, step int64, hashes []string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mfa store enable begin: %w", err)
	}
	// Rollback after commit is a no-op; the error is deliberately ignored so it
	// cannot mask the real result.
	defer func() { _ = tx.Rollback() }()

	const enable = `
		UPDATE user_mfa
		SET enabled_at = ?, last_step = ?, updated_at = ?
		WHERE user_id = ? AND enabled_at IS NULL`
	res, err := tx.ExecContext(ctx, enable, now, step, now, userID)
	if err != nil {
		return fmt.Errorf("mfa store enable: %w", err)
	}
	if err := requireRows(res, "mfa store enable", ErrNotPending); err != nil {
		return err
	}

	if err := replaceRecoveryCodes(ctx, tx, userID, hashes, now); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("mfa store enable commit: %w", err)
	}
	return nil
}

// AcceptStep records step as the last accepted TOTP step. The WHERE guard makes
// this the atomic anti-replay check: two racing requests presenting the same
// code can only win once. A false result with a nil error means the step was
// already consumed.
func (s *Store) AcceptStep(ctx context.Context, userID string, step int64, now time.Time) (bool, error) {
	const query = `
		UPDATE user_mfa SET last_step = ?, updated_at = ?
		WHERE user_id = ? AND enabled_at IS NOT NULL AND last_step < ?`
	res, err := s.db.ExecContext(ctx, query, step, now, userID, step)
	if err != nil {
		return false, fmt.Errorf("mfa store accept step: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mfa store accept step rows: %w", err)
	}
	return n > 0, nil
}

// ReplaceRecoveryCodes swaps the user's recovery-code set. Unused codes from
// the old set stop working immediately.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes []string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mfa store replace codes begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := replaceRecoveryCodes(ctx, tx, userID, hashes, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("mfa store replace codes commit: %w", err)
	}
	return nil
}

// replaceRecoveryCodes is the transaction body shared by enrollment and
// regeneration.
func replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, userID string, hashes []string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("mfa store clear recovery codes: %w", err)
	}
	const insert = `
		INSERT INTO user_mfa_recovery_codes (user_id, hash, created_at)
		VALUES (?, ?, ?)`
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, insert, userID, h, now); err != nil {
			return fmt.Errorf("mfa store insert recovery code: %w", err)
		}
	}
	return nil
}

// ConsumeRecoveryCode marks one unused recovery code as used. The UPDATE is the
// single-use guarantee: a code can only be claimed once, even under concurrent
// requests. A false result with a nil error means the code is unknown or spent.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID, hash string, now time.Time) (bool, error) {
	const query = `
		UPDATE user_mfa_recovery_codes SET used_at = ?
		WHERE user_id = ? AND hash = ? AND used_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, now, userID, hash)
	if err != nil {
		return false, fmt.Errorf("mfa store consume recovery code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mfa store consume recovery code rows: %w", err)
	}
	return n > 0, nil
}

// RemainingRecoveryCodes counts unused recovery codes.
func (s *Store) RemainingRecoveryCodes(ctx context.Context, userID string) (int, error) {
	const query = `
		SELECT COUNT(*) FROM user_mfa_recovery_codes
		WHERE user_id = ? AND used_at IS NULL`
	var n int
	if err := s.db.QueryRowContext(ctx, query, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("mfa store remaining recovery codes: %w", err)
	}
	return n, nil
}

// Delete removes everything MFA-related for one user: the credential, its
// recovery codes, and any live login challenge. Used by self-service disable
// and by the admin reset.
func (s *Store) Delete(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mfa store delete begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, query := range []string{
		`DELETE FROM user_mfa WHERE user_id = ?`,
		`DELETE FROM user_mfa_recovery_codes WHERE user_id = ?`,
		`DELETE FROM mfa_challenges WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, query, userID); err != nil {
			return fmt.Errorf("mfa store delete: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("mfa store delete commit: %w", err)
	}
	return nil
}

// ListEnabledIDs returns the IDs of every user with a completed enrollment, for
// the admin user list. One query for the whole page, never one per row.
func (s *Store) ListEnabledIDs(ctx context.Context) ([]string, error) {
	const query = `SELECT user_id FROM user_mfa WHERE enabled_at IS NOT NULL`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("mfa store list enabled: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("mfa store list enabled scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mfa store list enabled rows: %w", err)
	}
	return ids, nil
}

// CreateChallenge inserts a pending second-factor challenge. The token is
// generated by the service (crypto/rand, 32 bytes) and is the cookie value.
func (s *Store) CreateChallenge(ctx context.Context, token, userID, returnTo string, expiresAt, now time.Time) error {
	const query = `
		INSERT INTO mfa_challenges (token, user_id, return_to, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, token, userID, returnTo, expiresAt, now); err != nil {
		return fmt.Errorf("mfa store create challenge: %w", err)
	}
	return nil
}

// GetChallenge looks up a challenge by token. Expiry is evaluated by the
// caller's clock, not SQLite's, so tests can advance time deterministically.
func (s *Store) GetChallenge(ctx context.Context, token string) (*Challenge, error) {
	const query = `
		SELECT token, user_id, return_to, expires_at, created_at
		FROM mfa_challenges WHERE token = ?`
	var c Challenge
	err := s.db.QueryRowContext(ctx, query, token).
		Scan(&c.Token, &c.UserID, &c.ReturnTo, &c.ExpiresAt, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("mfa store get challenge: %w", err)
	}
	return &c, nil
}

// DeleteChallenge removes one challenge.
func (s *Store) DeleteChallenge(ctx context.Context, token string) error {
	const query = `DELETE FROM mfa_challenges WHERE token = ?`
	if _, err := s.db.ExecContext(ctx, query, token); err != nil {
		return fmt.Errorf("mfa store delete challenge: %w", err)
	}
	return nil
}

// DeleteExpiredChallenges removes challenges that expired before cutoff.
func (s *Store) DeleteExpiredChallenges(ctx context.Context, cutoff time.Time) error {
	const query = `DELETE FROM mfa_challenges WHERE expires_at < ?`
	if _, err := s.db.ExecContext(ctx, query, cutoff); err != nil {
		return fmt.Errorf("mfa store delete expired challenges: %w", err)
	}
	return nil
}

// ReencryptSecrets rewrites every secret still stored in plain text, returning
// how many rows it changed. It is the one-time upgrade pass for a database
// written by a release that did not encrypt secrets.
//
// The pass is sequential and simple by design: db.Open keeps a single writer
// connection, so rows are collected first and updated afterwards (issuing an
// UPDATE while a result set is open would block on that connection). Each
// UPDATE matches the old value, which makes a second run a no-op and makes a
// concurrent re-enrollment win instead of being clobbered. updated_at is left
// alone: re-encryption is not a change the user made.
//
// A nil cipher has nothing to migrate and returns (0, nil).
func (s *Store) ReencryptSecrets(ctx context.Context) (int, error) {
	if s.cipher == nil {
		return 0, nil
	}
	pending, err := s.plaintextSecrets(ctx)
	if err != nil {
		return 0, err
	}

	changed := 0
	for _, row := range pending {
		encrypted, err := s.cipher.Encrypt(row.secret, row.userID)
		if err != nil {
			return changed, fmt.Errorf("mfa store reencrypt: %w", err)
		}
		const query = `UPDATE user_mfa SET secret = ? WHERE user_id = ? AND secret = ?`
		res, err := s.db.ExecContext(ctx, query, encrypted, row.userID, row.secret)
		if err != nil {
			return changed, fmt.Errorf("mfa store reencrypt: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return changed, fmt.Errorf("mfa store reencrypt rows: %w", err)
		}
		changed += int(n)
	}
	return changed, nil
}

// legacySecret is a raw user_mfa row as it sits in the database, before any
// decryption — the input to the re-encryption pass.
type legacySecret struct {
	userID string
	secret string
}

// plaintextSecrets lists the rows whose stored value is not yet encrypted. It
// reads the raw column: decrypting here would defeat the point, and legacy
// values pass through unchanged anyway.
func (s *Store) plaintextSecrets(ctx context.Context) ([]legacySecret, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, secret FROM user_mfa`)
	if err != nil {
		return nil, fmt.Errorf("mfa store list plaintext secrets: %w", err)
	}
	defer rows.Close()

	var pending []legacySecret
	for rows.Next() {
		var row legacySecret
		if err := rows.Scan(&row.userID, &row.secret); err != nil {
			return nil, fmt.Errorf("mfa store list plaintext secrets scan: %w", err)
		}
		if !IsEncrypted(row.secret) {
			pending = append(pending, row)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mfa store list plaintext secrets rows: %w", err)
	}
	return pending, nil
}

// encryptSecret seals secret for userID, or returns it unchanged when the store
// has no cipher.
func (s *Store) encryptSecret(userID, secret string) (string, error) {
	if s.cipher == nil {
		return secret, nil
	}
	encrypted, err := s.cipher.Encrypt(secret, userID)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}

// decryptSecret opens secret for userID. A legacy plaintext value comes back
// unchanged, which is what keeps an upgraded database usable before (or
// without) ReencryptSecrets.
func (s *Store) decryptSecret(userID, secret string) (string, error) {
	if s.cipher == nil {
		return secret, nil
	}
	return s.cipher.Decrypt(secret, userID)
}

// requireRows turns a zero-rows-affected result into the given error.
func requireRows(res sql.Result, op string, zero error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows affected: %w", op, err)
	}
	if n == 0 {
		return zero
	}
	return nil
}
