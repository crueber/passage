package idp

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultScopes is the scope set used when a provider does not list any. Every
// upstream flow needs openid to receive an id_token; email is required to link
// a verified address to an existing account.
func DefaultScopes() []string {
	return []string{"openid", "email", "profile"}
}

// providerNameRe constrains slugs: the name is a URL path segment.
var providerNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// ErrProviderNotFound reports an unknown provider id or name.
var ErrProviderNotFound = errors.New("idp: provider not found")

// SecretCipher seals and opens client secrets at rest. Implemented by
// *mfa.Cipher in production; tests may use a pass-through.
type SecretCipher interface {
	Encrypt(secret, aad string) (string, error)
	Decrypt(value, aad string) (string, error)
}

// ProviderStore is the SQLite-backed list of upstream providers. The client
// secret is stored sealed and is only decrypted when a provider is read.
type ProviderStore struct {
	db     *sql.DB
	cipher SecretCipher
}

// NewProviderStore returns a store using cipher for client secrets. A nil
// cipher stores the secret as-is, which exists only for tests.
func NewProviderStore(db *sql.DB, cipher SecretCipher) *ProviderStore {
	return &ProviderStore{db: db, cipher: cipher}
}

const providerColumns = `id, name, label, issuer, client_id, client_secret, scopes, auto_create, created_at, updated_at`

// List returns every provider ordered by name.
func (s *ProviderStore) List(ctx context.Context) ([]*Provider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+providerColumns+` FROM idp_providers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("idp store list providers: %w", err)
	}
	defer rows.Close()

	var out []*Provider
	for rows.Next() {
		p, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("idp store list providers rows: %w", err)
	}
	return out, nil
}

// Get resolves a provider by its route name.
func (s *ProviderStore) Get(ctx context.Context, name string) (*Provider, error) {
	return s.getOne(ctx, `SELECT `+providerColumns+` FROM idp_providers WHERE name = ?`, name)
}

// GetByID resolves a provider by its id (the admin edit page).
func (s *ProviderStore) GetByID(ctx context.Context, id string) (*Provider, error) {
	return s.getOne(ctx, `SELECT `+providerColumns+` FROM idp_providers WHERE id = ?`, id)
}

func (s *ProviderStore) getOne(ctx context.Context, query, arg string) (*Provider, error) {
	row := s.db.QueryRowContext(ctx, query, arg)
	p, err := s.scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProviderNotFound
	}
	return p, err
}

// Create inserts a provider. A missing id is generated; the label defaults to
// the name and the scopes to DefaultScopes. A duplicate name is reported as an
// error by SQLite's unique constraint.
func (s *ProviderStore) Create(ctx context.Context, p *Provider) error {
	if p.ID == "" {
		p.ID = randomID()
	}
	normalizeProvider(p)
	sealed, err := s.seal(p)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO idp_providers (id, name, label, issuer, client_id, client_secret, scopes, auto_create)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.Label, p.Issuer, p.ClientID, sealed, strings.Join(p.Scopes, "\n"), boolInt(p.AutoCreate))
	if err != nil {
		return fmt.Errorf("idp store create provider: %w", err)
	}
	return nil
}

// Update rewrites a provider by id. An empty ClientSecret keeps the stored one,
// so the edit form does not have to echo the secret back.
func (s *ProviderStore) Update(ctx context.Context, p *Provider) error {
	normalizeProvider(p)
	sealed := ""
	if p.ClientSecret != "" {
		var err error
		if sealed, err = s.seal(p); err != nil {
			return err
		}
	}
	var err error
	if sealed == "" {
		_, err = s.db.ExecContext(ctx,
			`UPDATE idp_providers SET name = ?, label = ?, issuer = ?, client_id = ?, scopes = ?,
			        auto_create = ?, updated_at = ?
			 WHERE id = ?`,
			p.Name, p.Label, p.Issuer, p.ClientID, strings.Join(p.Scopes, "\n"),
			boolInt(p.AutoCreate), time.Now().UTC(), p.ID)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE idp_providers SET name = ?, label = ?, issuer = ?, client_id = ?, client_secret = ?,
			        scopes = ?, auto_create = ?, updated_at = ?
			 WHERE id = ?`,
			p.Name, p.Label, p.Issuer, p.ClientID, sealed,
			strings.Join(p.Scopes, "\n"), boolInt(p.AutoCreate), time.Now().UTC(), p.ID)
	}
	if err != nil {
		return fmt.Errorf("idp store update provider: %w", err)
	}
	return nil
}

// Delete removes a provider by id.
func (s *ProviderStore) Delete(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM idp_providers WHERE id = ?`, id); err != nil {
		return fmt.Errorf("idp store delete provider: %w", err)
	}
	return nil
}

// Count reports how many providers exist (the login page hides the section when
// there are none).
func (s *ProviderStore) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM idp_providers`).Scan(&n); err != nil {
		return 0, fmt.Errorf("idp store count providers: %w", err)
	}
	return n, nil
}

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func (s *ProviderStore) scan(row rowScanner) (*Provider, error) {
	var p Provider
	var scopes string
	var autoCreate int
	var created, updated time.Time
	if err := row.Scan(&p.ID, &p.Name, &p.Label, &p.Issuer, &p.ClientID, &p.sealed, &scopes, &autoCreate, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("idp store scan provider: %w", err)
	}
	p.Scopes = splitLines(scopes)
	p.AutoCreate = autoCreate != 0
	p.CreatedAt, p.UpdatedAt = created, updated
	if s.cipher != nil && p.sealed != "" {
		secret, err := s.cipher.Decrypt(p.sealed, p.ID)
		if err != nil {
			return nil, fmt.Errorf("idp store decrypt secret for %q: %w", p.Name, err)
		}
		p.ClientSecret = secret
	} else {
		p.ClientSecret = p.sealed
	}
	p.sealed = ""
	return &p, nil
}

func (s *ProviderStore) seal(p *Provider) (string, error) {
	if s.cipher == nil {
		return p.ClientSecret, nil
	}
	sealed, err := s.cipher.Encrypt(p.ClientSecret, p.ID)
	if err != nil {
		return "", fmt.Errorf("idp store seal secret for %q: %w", p.Name, err)
	}
	return sealed, nil
}

// ValidateProvider checks the fields the admin form submits. The name is
// unique-checked by the database.
func ValidateProvider(p *Provider) error {
	var errs []error
	if !providerNameRe.MatchString(p.Name) || len(p.Name) > 64 {
		errs = append(errs, errors.New("name must be a lowercase slug of 1–64 characters ([a-z0-9][a-z0-9_-]*)"))
	}
	u, err := url.Parse(p.Issuer)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("issuer is not a valid URL: %w", err))
	case !strings.EqualFold(u.Scheme, "https"):
		errs = append(errs, fmt.Errorf("issuer must use https, got %q", u.Scheme))
	case u.Host == "":
		errs = append(errs, errors.New("issuer must include a host"))
	case u.User != nil:
		errs = append(errs, errors.New("issuer must not include user information"))
	case u.RawQuery != "" || u.Fragment != "":
		errs = append(errs, errors.New("issuer must not include a query or fragment"))
	}
	if p.ClientID == "" {
		errs = append(errs, errors.New("client id must not be empty"))
	}
	if p.ClientSecret == "" {
		errs = append(errs, errors.New("client secret must not be empty"))
	}
	hasOpenID := false
	for _, scope := range p.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			errs = append(errs, fmt.Errorf("scopes contains an invalid scope %q", scope))
			continue
		}
		if scope == "openid" {
			hasOpenID = true
		}
	}
	if len(p.Scopes) == 0 || !hasOpenID {
		errs = append(errs, errors.New(`scopes must include "openid"`))
	}
	return errors.Join(errs...)
}

// normalizeProvider trims and defaults the fields shared by create and update.
func normalizeProvider(p *Provider) {
	p.Name = strings.TrimSpace(p.Name)
	p.Label = strings.TrimSpace(p.Label)
	if p.Label == "" {
		p.Label = p.Name
	}
	p.Issuer = strings.TrimSpace(p.Issuer)
	p.ClientID = strings.TrimSpace(p.ClientID)
	if len(p.Scopes) == 0 {
		p.Scopes = DefaultScopes()
	}
	for i, s := range p.Scopes {
		p.Scopes[i] = strings.TrimSpace(s)
	}
}

func splitLines(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is unrecoverable; a timestamp keeps the row
		// addressable rather than panicking in a request.
		return fmt.Sprintf("provider-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
