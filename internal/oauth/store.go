package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
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

// generateToken generates a cryptographically random 64-character hex string.
// It is used as the value for codes, access tokens, and refresh tokens.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateCode inserts a new authorization code into the database.
// A random 64-char hex token is assigned to code.Code before inserting.
func (s *SQLiteStore) CreateCode(ctx context.Context, c *Code) error {
	token, err := generateToken()
	if err != nil {
		return err
	}
	c.Code = token

	now := time.Now().UTC()
	c.CreatedAt = now

	const query = `
		INSERT INTO oauth_codes (code, app_id, user_id, redirect_uri, scopes, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		c.Code, c.AppID, c.UserID, c.RedirectURI, c.Scopes,
		c.ExpiresAt, c.CreatedAt, now,
	)
	if err != nil {
		return fmt.Errorf("oauth store create code: %w", err)
	}
	return nil
}

// GetCode looks up an authorization code by its value.
// Returns ErrCodeNotFound if the code does not exist.
func (s *SQLiteStore) GetCode(ctx context.Context, code string) (*Code, error) {
	const query = `
		SELECT code, app_id, user_id, redirect_uri, scopes, expires_at, used_at, created_at
		FROM oauth_codes WHERE code = ?`

	row := s.db.QueryRowContext(ctx, query, code)
	var c Code
	var usedAt sql.NullTime
	err := row.Scan(
		&c.Code, &c.AppID, &c.UserID, &c.RedirectURI, &c.Scopes,
		&c.ExpiresAt, &usedAt, &c.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrCodeNotFound
		}
		return nil, fmt.Errorf("oauth store get code: %w", err)
	}
	if usedAt.Valid {
		t := usedAt.Time
		c.UsedAt = &t
	}
	return &c, nil
}

// MarkCodeUsed sets the used_at timestamp on an authorization code.
func (s *SQLiteStore) MarkCodeUsed(ctx context.Context, code string) error {
	const query = `
		UPDATE oauth_codes SET used_at = ?, updated_at = ?
		WHERE code = ?`

	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, query, now, now, code)
	if err != nil {
		return fmt.Errorf("oauth store mark code used: %w", err)
	}
	return nil
}

// CreateToken inserts a new access token into the database.
// A random 64-char hex token is assigned to token.Token before inserting.
func (s *SQLiteStore) CreateToken(ctx context.Context, t *Token) error {
	tok, err := generateToken()
	if err != nil {
		return err
	}
	t.Token = tok

	now := time.Now().UTC()
	t.CreatedAt = now

	const query = `
		INSERT INTO oauth_tokens (token, app_id, user_id, scopes, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		t.Token, t.AppID, t.UserID, t.Scopes, t.ExpiresAt, t.CreatedAt, now,
	)
	if err != nil {
		return fmt.Errorf("oauth store create token: %w", err)
	}
	return nil
}

// GetToken looks up an access token by its value.
// Returns ErrTokenNotFound if the token does not exist.
func (s *SQLiteStore) GetToken(ctx context.Context, token string) (*Token, error) {
	const query = `
		SELECT token, app_id, user_id, scopes, expires_at, created_at
		FROM oauth_tokens WHERE token = ?`

	row := s.db.QueryRowContext(ctx, query, token)
	var t Token
	err := row.Scan(&t.Token, &t.AppID, &t.UserID, &t.Scopes, &t.ExpiresAt, &t.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("oauth store get token: %w", err)
	}
	return &t, nil
}

// DeleteToken removes an access token by its value.
func (s *SQLiteStore) DeleteToken(ctx context.Context, token string) error {
	const query = `DELETE FROM oauth_tokens WHERE token = ?`
	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("oauth store delete token: %w", err)
	}
	return nil
}

// CreateRefreshToken inserts a new refresh token into the database.
// A random 64-char hex token is assigned to rt.Token before inserting.
func (s *SQLiteStore) CreateRefreshToken(ctx context.Context, rt *RefreshToken) error {
	tok, err := generateToken()
	if err != nil {
		return err
	}
	rt.Token = tok

	now := time.Now().UTC()
	rt.CreatedAt = now

	const query = `
		INSERT INTO oauth_refresh_tokens (token, app_id, user_id, scopes, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		rt.Token, rt.AppID, rt.UserID, rt.Scopes, rt.ExpiresAt, rt.CreatedAt, now,
	)
	if err != nil {
		return fmt.Errorf("oauth store create refresh token: %w", err)
	}
	return nil
}

// GetRefreshToken looks up a refresh token by its value.
// Returns ErrRefreshNotFound if the token does not exist.
func (s *SQLiteStore) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	const query = `
		SELECT token, app_id, user_id, scopes, expires_at, used_at, created_at
		FROM oauth_refresh_tokens WHERE token = ?`

	row := s.db.QueryRowContext(ctx, query, token)
	var rt RefreshToken
	var usedAt sql.NullTime
	err := row.Scan(
		&rt.Token, &rt.AppID, &rt.UserID, &rt.Scopes,
		&rt.ExpiresAt, &usedAt, &rt.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRefreshNotFound
		}
		return nil, fmt.Errorf("oauth store get refresh token: %w", err)
	}
	if usedAt.Valid {
		t := usedAt.Time
		rt.UsedAt = &t
	}
	return &rt, nil
}

// MarkRefreshTokenUsed sets the used_at timestamp on a refresh token.
func (s *SQLiteStore) MarkRefreshTokenUsed(ctx context.Context, token string) error {
	const query = `
		UPDATE oauth_refresh_tokens SET used_at = ?, updated_at = ?
		WHERE token = ?`

	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, query, now, now, token)
	if err != nil {
		return fmt.Errorf("oauth store mark refresh token used: %w", err)
	}
	return nil
}

// DeleteExpired removes all expired authorization codes, access tokens, and
// refresh tokens from the database.
func (s *SQLiteStore) DeleteExpired(ctx context.Context) error {
	now := time.Now().UTC()

	queries := []string{
		`DELETE FROM oauth_codes WHERE expires_at < ?`,
		`DELETE FROM oauth_tokens WHERE expires_at < ?`,
		`DELETE FROM oauth_refresh_tokens WHERE expires_at < ?`,
	}

	for _, q := range queries {
		if _, err := s.db.ExecContext(ctx, q, now); err != nil {
			return fmt.Errorf("oauth store delete expired: %w", err)
		}
	}
	return nil
}

// GetOrCreateRSAKey returns the stored RSA private key PEM from oidc_config,
// creating and storing a new 2048-bit RSA key if none exists.
// Uses INSERT OR IGNORE + read-back to be safe against concurrent startup.
func (s *SQLiteStore) GetOrCreateRSAKey(ctx context.Context) ([]byte, error) {
	// Try to read existing key first.
	const selectQuery = `SELECT value FROM oidc_config WHERE key = 'rsa_private_key'`
	var pemStr string
	err := s.db.QueryRowContext(ctx, selectQuery).Scan(&pemStr)
	if err == nil {
		return []byte(pemStr), nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("oauth store get rsa key: %w", err)
	}

	// No key found — generate a new one.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oauth store generate rsa key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	now := time.Now().UTC()
	const insertQuery = `
		INSERT OR IGNORE INTO oidc_config (key, value, created_at, updated_at)
		VALUES ('rsa_private_key', ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, insertQuery, string(pemBytes), now, now)
	if err != nil {
		return nil, fmt.Errorf("oauth store insert rsa key: %w", err)
	}

	// Read back what was actually stored (another process may have won the race).
	var stored string
	if err := s.db.QueryRowContext(ctx, selectQuery).Scan(&stored); err != nil {
		return nil, fmt.Errorf("oauth store read back rsa key: %w", err)
	}
	return []byte(stored), nil
}
