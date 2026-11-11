package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
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
		INSERT INTO oauth_codes (code, app_id, user_id, redirect_uri, scopes, nonce, auth_time,
		                         resource, code_challenge, code_challenge_method,
		                         expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		c.Code, c.AppID, c.UserID, c.RedirectURI, c.Scopes,
		c.Nonce, c.AuthTime, c.Resource,
		c.CodeChallenge, string(c.CodeChallengeMethod),
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
		SELECT code, app_id, user_id, redirect_uri, scopes, nonce, auth_time, resource,
		       code_challenge, code_challenge_method,
		       expires_at, used_at, created_at
		FROM oauth_codes WHERE code = ?`

	row := s.db.QueryRowContext(ctx, query, code)
	var c Code
	var usedAt sql.NullTime
	var codeChallenge sql.NullString
	var codeChallengeMethod sql.NullString
	err := row.Scan(
		&c.Code, &c.AppID, &c.UserID, &c.RedirectURI, &c.Scopes,
		&c.Nonce, &c.AuthTime, &c.Resource,
		&codeChallenge, &codeChallengeMethod,
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
	if codeChallenge.Valid {
		c.CodeChallenge = codeChallenge.String
	}
	if codeChallengeMethod.Valid {
		c.CodeChallengeMethod = PKCEMethod(codeChallengeMethod.String)
	}
	return &c, nil
}

// MarkCodeUsed atomically marks the code as used if it has not already been used.
// Returns ErrCodeUsed if the code was already used (concurrent double-spend protection).
func (s *SQLiteStore) MarkCodeUsed(ctx context.Context, code string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE oauth_codes SET used_at = datetime('now'), updated_at = datetime('now') WHERE code = ? AND used_at IS NULL`,
		code,
	)
	if err != nil {
		return fmt.Errorf("oauth store mark code used: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("oauth store mark code used rows affected: %w", err)
	}
	if n == 0 {
		return ErrCodeUsed
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

// RevokeJTI denylists a JWT access token's jti. It is idempotent: revoking the
// same token twice keeps the first expiry. expiresAt is the token's own exp, so
// the row can be deleted once the token could no longer be accepted anyway.
func (s *SQLiteStore) RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) error {
	if jti == "" {
		return fmt.Errorf("oauth store revoke jti: empty jti")
	}
	const query = `
		INSERT INTO oauth_revoked_jti (jti, expires_at, revoked_at)
		VALUES (?, ?, ?)
		ON CONFLICT(jti) DO NOTHING`
	if _, err := s.db.ExecContext(ctx, query, jti, expiresAt, time.Now().UTC()); err != nil {
		return fmt.Errorf("oauth store revoke jti: %w", err)
	}
	return nil
}

// IsJTIRevoked reports whether a JWT access token has been revoked.
func (s *SQLiteStore) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	const query = `SELECT COUNT(*) FROM oauth_revoked_jti WHERE jti = ?`
	var n int
	if err := s.db.QueryRowContext(ctx, query, jti).Scan(&n); err != nil {
		return false, fmt.Errorf("oauth store check revoked jti: %w", err)
	}
	return n > 0, nil
}

// CreateRefreshToken inserts a new refresh token into the database.
// A random 64-char hex token is assigned to rt.Token before inserting.
// When rt.FamilyID is empty a fresh family is generated — this is the start of
// a rotation chain. Rotation passes the parent's FamilyID through unchanged.
func (s *SQLiteStore) CreateRefreshToken(ctx context.Context, rt *RefreshToken) error {
	tok, err := generateToken()
	if err != nil {
		return err
	}
	rt.Token = tok

	if rt.FamilyID == "" {
		familyID, err := generateToken()
		if err != nil {
			return err
		}
		rt.FamilyID = familyID
	}

	now := time.Now().UTC()
	rt.CreatedAt = now

	const query = `
		INSERT INTO oauth_refresh_tokens (token, app_id, user_id, scopes, family_id, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		rt.Token, rt.AppID, rt.UserID, rt.Scopes, rt.FamilyID, rt.ExpiresAt, rt.CreatedAt, now,
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
		SELECT token, app_id, user_id, scopes, family_id, expires_at, used_at, created_at
		FROM oauth_refresh_tokens WHERE token = ?`

	row := s.db.QueryRowContext(ctx, query, token)
	var rt RefreshToken
	var usedAt sql.NullTime
	err := row.Scan(
		&rt.Token, &rt.AppID, &rt.UserID, &rt.Scopes, &rt.FamilyID,
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

// MarkRefreshTokenUsed atomically marks the refresh token as used if it has not already been used.
// Returns ErrRefreshUsed if the token was already used (concurrent double-spend protection).
func (s *SQLiteStore) MarkRefreshTokenUsed(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE oauth_refresh_tokens SET used_at = datetime('now'), updated_at = datetime('now') WHERE token = ? AND used_at IS NULL`,
		token,
	)
	if err != nil {
		return fmt.Errorf("oauth store mark refresh token used: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("oauth store mark refresh token used rows affected: %w", err)
	}
	if n == 0 {
		return ErrRefreshUsed
	}
	return nil
}

// DeleteRefreshFamily removes every refresh token belonging to familyID, which
// ends the whole rotation chain. An empty familyID is a no-op: pre-migration
// rows are backfilled, so an empty value would only be a caller bug, and
// deleting on it would wipe unrelated tokens.
func (s *SQLiteStore) DeleteRefreshFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_refresh_tokens WHERE family_id = ?`, familyID)
	if err != nil {
		return fmt.Errorf("oauth store delete refresh family: %w", err)
	}
	return nil
}

// DeleteExpired removes all expired authorization codes, access tokens, and
// refresh tokens from the database. Used codes and refresh tokens are also
// removed regardless of expiry, since they can never be reused. Denylisted
// access-token jtis are removed once the token itself would have expired: the
// signature check rejects it after that, so the row adds nothing.
func (s *SQLiteStore) DeleteExpired(ctx context.Context) error {
	queries := []string{
		`DELETE FROM oauth_codes WHERE expires_at < datetime('now') OR used_at IS NOT NULL`,
		`DELETE FROM oauth_tokens WHERE expires_at < datetime('now')`,
		`DELETE FROM oauth_refresh_tokens WHERE expires_at < datetime('now') OR used_at IS NOT NULL`,
		`DELETE FROM oauth_revoked_jti WHERE expires_at < datetime('now')`,
	}

	for _, q := range queries {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("oauth store delete expired: %w", err)
		}
	}
	return nil
}

// legacyRSAKeyName is the oidc_config key that held the single RSA key before
// kid history existed. It is imported once and deliberately left in place: an
// older binary rolling back still reads it.
const legacyRSAKeyName = "rsa_private_key"

// signingKeyBits is the RSA modulus size for signing keys.
const signingKeyBits = 2048

// EnsureSigningKeys makes sure the keyring can sign. It is idempotent and is
// called at startup:
//
//   - any non-retired key means there is nothing to do;
//   - an empty table imports the legacy oidc_config RSA key with its derived
//     kid, so existing id_tokens keep verifying and the JWKS does not change;
//   - otherwise (no legacy key, or every row retired by hand) a new 2048-bit
//     RSA key is generated, because an issuer that cannot sign is down.
//
// The thumbprint is always computed in Go, never in SQL.
func (s *SQLiteStore) EnsureSigningKeys(ctx context.Context) error {
	var total, active int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(retired_at IS NULL), 0) FROM oauth_signing_keys`,
	).Scan(&total, &active); err != nil {
		return fmt.Errorf("oauth store count signing keys: %w", err)
	}
	if active > 0 {
		return nil
	}
	if total > 0 {
		// Every key is retired. Only direct SQL can reach this state (the API
		// refuses to retire the last key); keep the history and add a fresh key
		// so the server comes up.
		key, err := generateSigningKey()
		if err != nil {
			return err
		}
		return s.CreateSigningKey(ctx, key)
	}

	var (
		legacyPEM     string
		legacyCreated sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT value, created_at FROM oidc_config WHERE key = ?`, legacyRSAKeyName,
	).Scan(&legacyPEM, &legacyCreated)
	switch {
	case err == nil:
		kid, err := deriveKID([]byte(legacyPEM))
		if err != nil {
			return fmt.Errorf("oauth store import legacy signing key: %w", err)
		}
		createdAt := time.Now().UTC()
		if legacyCreated.Valid && !legacyCreated.Time.IsZero() {
			createdAt = legacyCreated.Time.UTC()
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO oauth_signing_keys (kid, private_key_pem, created_at) VALUES (?, ?, ?)`,
			kid, legacyPEM, createdAt,
		); err != nil {
			return fmt.Errorf("oauth store import legacy signing key: %w", err)
		}
		return nil
	case err != sql.ErrNoRows:
		return fmt.Errorf("oauth store read legacy signing key: %w", err)
	}

	key, err := generateSigningKey()
	if err != nil {
		return err
	}
	return s.CreateSigningKey(ctx, key)
}

// ListSigningKeys returns every stored key, newest first, retired keys
// included. The kid is taken from the row: it was derived from this PEM when
// the row was written.
func (s *SQLiteStore) ListSigningKeys(ctx context.Context) ([]*SigningKey, error) {
	const query = `
		SELECT kid, private_key_pem, created_at, retired_at
		FROM oauth_signing_keys
		ORDER BY created_at DESC, rowid DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("oauth store list signing keys: %w", err)
	}
	defer rows.Close()

	var keys []*SigningKey
	for rows.Next() {
		var (
			kid       string
			pemStr    string
			createdAt sql.NullTime
			retiredAt sql.NullTime
		)
		if err := rows.Scan(&kid, &pemStr, &createdAt, &retiredAt); err != nil {
			return nil, fmt.Errorf("oauth store scan signing key: %w", err)
		}
		privateKey, err := parsePrivateKeyPEM([]byte(pemStr))
		if err != nil {
			return nil, fmt.Errorf("oauth store parse signing key %q: %w", kid, err)
		}
		key := &SigningKey{
			KID:        kid,
			CreatedAt:  createdAt.Time.UTC(),
			privateKey: privateKey,
		}
		if retiredAt.Valid {
			retired := retiredAt.Time.UTC()
			key.RetiredAt = &retired
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oauth store list signing keys: %w", err)
	}
	return keys, nil
}

// CreateSigningKey persists key, deriving its kid from the public key and
// stamping CreatedAt. The caller must set the private key.
func (s *SQLiteStore) CreateSigningKey(ctx context.Context, key *SigningKey) error {
	if key == nil || key.privateKey == nil {
		return fmt.Errorf("oauth store create signing key: missing private key")
	}
	pemBytes := marshalPrivateKeyPEM(key.privateKey)
	kid, err := deriveKID(pemBytes)
	if err != nil {
		return fmt.Errorf("oauth store create signing key: %w", err)
	}

	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth_signing_keys (kid, private_key_pem, created_at) VALUES (?, ?, ?)`,
		kid, string(pemBytes), now,
	); err != nil {
		return fmt.Errorf("oauth store create signing key: %w", err)
	}

	key.KID = kid
	key.CreatedAt = now
	key.RetiredAt = nil
	return nil
}

// RetireSigningKey marks kid retired. Retiring an already-retired key is a
// no-op, and the last non-retired key cannot be retired: rotating first keeps
// the issuer able to sign at all times.
func (s *SQLiteStore) RetireSigningKey(ctx context.Context, kid string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("oauth store retire signing key: %w", err)
	}
	// Rollback after a successful commit is a documented no-op; the error is
	// not actionable.
	defer func() { _ = tx.Rollback() }()

	var retiredAt sql.NullTime
	err = tx.QueryRowContext(ctx,
		`SELECT retired_at FROM oauth_signing_keys WHERE kid = ?`, kid,
	).Scan(&retiredAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrSigningKeyNotFound
		}
		return fmt.Errorf("oauth store retire signing key: %w", err)
	}
	if retiredAt.Valid {
		return tx.Commit()
	}

	var active int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oauth_signing_keys WHERE retired_at IS NULL`,
	).Scan(&active); err != nil {
		return fmt.Errorf("oauth store retire signing key: count active: %w", err)
	}
	if active <= 1 {
		return ErrSigningKeyLast
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE oauth_signing_keys SET retired_at = ? WHERE kid = ?`,
		time.Now().UTC(), kid,
	); err != nil {
		return fmt.Errorf("oauth store retire signing key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("oauth store retire signing key: commit: %w", err)
	}
	return nil
}

// DeleteSigningKey removes a retired key permanently. Active keys are refused
// so a key cannot disappear while it is still signing or verifying.
func (s *SQLiteStore) DeleteSigningKey(ctx context.Context, kid string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_signing_keys WHERE kid = ? AND retired_at IS NOT NULL`, kid,
	)
	if err != nil {
		return fmt.Errorf("oauth store delete signing key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("oauth store delete signing key: rows affected: %w", err)
	}
	if n > 0 {
		return nil
	}

	var exists int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oauth_signing_keys WHERE kid = ?`, kid,
	).Scan(&exists); err != nil {
		return fmt.Errorf("oauth store delete signing key: lookup: %w", err)
	}
	if exists == 0 {
		return ErrSigningKeyNotFound
	}
	return ErrSigningKeyActive
}

// generateSigningKey creates a new RSA private key for rotation.
func generateSigningKey() (*SigningKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, signingKeyBits)
	if err != nil {
		return nil, fmt.Errorf("oauth store generate signing key: %w", err)
	}
	return &SigningKey{privateKey: privateKey}, nil
}

// marshalPrivateKeyPEM encodes an RSA private key as a PKCS#1 PEM, the format
// earlier versions wrote to oidc_config.
func marshalPrivateKeyPEM(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

// parsePrivateKeyPEM decodes an RSA private key. PKCS#1 is what Passage has
// always written; PKCS#8 is accepted so a hand-migrated key still loads.
func parsePrivateKeyPEM(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want RSA", parsed)
	}
	return privateKey, nil
}

// deriveKID computes a stable key ID from the RSA private key PEM: the
// base64url SHA-256 of the public key's DER encoding. This is the same
// derivation earlier versions used, so importing the legacy key leaves every
// existing id_token verifiable.
func deriveKID(privateKeyPEM []byte) (string, error) {
	privateKey, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("deriveKID: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("deriveKID: marshal public key: %w", err)
	}
	sum := sha256.Sum256(pubDER)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
