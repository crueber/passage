package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// selectAppColumns is the ordered list of columns returned by all app SELECT
// queries. It must stay in sync with scanApp.
const selectAppColumns = `id, slug, name, description, host_pattern, default_url, is_active,
		session_duration_hours, created_at, updated_at,
		client_id, client_secret_hash, redirect_uris, oauth_enabled,
		scopes, resources,
		required_group, required_role, allowed_cidrs, admin_only, allowed_hours, allowed_days`

// selectAppColumnsAliased is the same column list but prefixed with a table
// alias "a." for use in queries that JOIN other tables to avoid ambiguity.
const selectAppColumnsAliased = `a.id, a.slug, a.name, a.description, a.host_pattern, a.default_url, a.is_active,
		a.session_duration_hours, a.created_at, a.updated_at,
		a.client_id, a.client_secret_hash, a.redirect_uris, a.oauth_enabled,
		a.scopes, a.resources,
		a.required_group, a.required_role, a.allowed_cidrs, a.admin_only, a.allowed_hours, a.allowed_days`

// SQLiteStore implements Store and AccessStore using a SQLite database.
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

// Create inserts a new app into the database.
// A new UUID is assigned to app.ID before inserting.
func (s *SQLiteStore) Create(ctx context.Context, a *App) error {
	id, err := newUUID()
	if err != nil {
		return fmt.Errorf("app store create: %w", err)
	}
	a.ID = id

	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now

	const query = `
		INSERT INTO apps (id, slug, name, description, host_pattern, default_url, is_active,
		                  session_duration_hours, created_at, updated_at,
		                  client_id, client_secret_hash, redirect_uris, oauth_enabled,
		                  scopes, resources,
		                  required_group, required_role, allowed_cidrs, admin_only, allowed_hours, allowed_days)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		a.ID, a.Slug, a.Name, a.Description, a.HostPattern, a.DefaultURL,
		boolToInt(a.IsActive), a.SessionDurationHours, a.CreatedAt, a.UpdatedAt,
		nullableString(a.ClientID), nullableString(a.ClientSecretHash),
		joinLines(a.RedirectURIs), boolToInt(a.OAuthEnabled),
		joinLines(a.AllowedScopes), joinLines(a.AllowedResources),
		a.RequiredGroup, a.RequiredRole, a.AllowedCIDRs, boolToInt(a.AdminOnly),
		a.AllowedHours, a.AllowedDays,
	)
	if err != nil {
		return mapAppConstraintError(err)
	}
	return nil
}

// GetByID looks up an app by its UUID.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*App, error) {
	const query = `
		SELECT ` + selectAppColumns + `
		FROM apps WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, id)
	a, err := scanApp(row)
	if err != nil {
		return nil, fmt.Errorf("app store get by id: %w", err)
	}
	return a, nil
}

// GetBySlug looks up an app by its slug.
func (s *SQLiteStore) GetBySlug(ctx context.Context, slug string) (*App, error) {
	const query = `
		SELECT ` + selectAppColumns + `
		FROM apps WHERE slug = ?`
	row := s.db.QueryRowContext(ctx, query, slug)
	a, err := scanApp(row)
	if err != nil {
		return nil, fmt.Errorf("app store get by slug: %w", err)
	}
	return a, nil
}

// GetByClientID looks up an app by its OAuth client_id.
func (s *SQLiteStore) GetByClientID(ctx context.Context, clientID string) (*App, error) {
	const query = `
		SELECT ` + selectAppColumns + `
		FROM apps WHERE client_id = ?`
	row := s.db.QueryRowContext(ctx, query, clientID)
	a, err := scanApp(row)
	if err != nil {
		return nil, fmt.Errorf("app store get by client id: %w", err)
	}
	return a, nil
}

// ListActive returns all active apps ordered by creation time ascending.
func (s *SQLiteStore) ListActive(ctx context.Context) ([]*App, error) {
	const query = `
		SELECT ` + selectAppColumns + `
		FROM apps WHERE is_active = 1 ORDER BY created_at ASC`
	return s.queryApps(ctx, query)
}

// List returns all apps ordered by name.
func (s *SQLiteStore) List(ctx context.Context) ([]*App, error) {
	const query = `
		SELECT ` + selectAppColumns + `
		FROM apps ORDER BY name`
	return s.queryApps(ctx, query)
}

// Count returns the number of apps, including inactive ones. It is a single
// COUNT query used by the metrics endpoint.
func (s *SQLiteStore) Count(ctx context.Context) (int, error) {
	const query = `SELECT COUNT(*) FROM apps`

	var n int
	if err := s.db.QueryRowContext(ctx, query).Scan(&n); err != nil {
		return 0, fmt.Errorf("app store count: %w", err)
	}
	return n, nil
}

// queryApps is a helper that executes a query returning app rows.
func (s *SQLiteStore) queryApps(ctx context.Context, query string, args ...any) ([]*App, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("app store query: %w", err)
	}
	defer rows.Close()

	var apps []*App
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, fmt.Errorf("app store query scan: %w", err)
		}
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("app store query rows: %w", err)
	}
	return apps, nil
}

// Update saves changes to an existing app.
func (s *SQLiteStore) Update(ctx context.Context, a *App) error {
	a.UpdatedAt = time.Now().UTC()

	const query = `
		UPDATE apps
		SET slug = ?, name = ?, description = ?, host_pattern = ?, default_url = ?,
		    is_active = ?, session_duration_hours = ?, updated_at = ?,
		    client_id = ?, client_secret_hash = ?, redirect_uris = ?, oauth_enabled = ?,
		    scopes = ?, resources = ?,
		    required_group = ?, required_role = ?, allowed_cidrs = ?, admin_only = ?,
		    allowed_hours = ?, allowed_days = ?
		WHERE id = ?`

	res, err := s.db.ExecContext(ctx, query,
		a.Slug, a.Name, a.Description, a.HostPattern, a.DefaultURL,
		boolToInt(a.IsActive), a.SessionDurationHours, a.UpdatedAt,
		nullableString(a.ClientID), nullableString(a.ClientSecretHash),
		joinLines(a.RedirectURIs), boolToInt(a.OAuthEnabled),
		joinLines(a.AllowedScopes), joinLines(a.AllowedResources),
		a.RequiredGroup, a.RequiredRole, a.AllowedCIDRs, boolToInt(a.AdminOnly),
		a.AllowedHours, a.AllowedDays,
		a.ID,
	)
	if err != nil {
		return fmt.Errorf("app store update: %w", mapAppConstraintError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("app store update rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("app store update: %w", ErrNotFound)
	}
	return nil
}

// Delete removes an app by ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	const query = `DELETE FROM apps WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("app store delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("app store delete rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("app store delete: %w", ErrNotFound)
	}
	return nil
}

// GrantAccess grants user access to an app. Uses INSERT OR IGNORE to be
// idempotent — granting access to a user who already has it is a no-op.
func (s *SQLiteStore) GrantAccess(ctx context.Context, userID, appID string) error {
	const query = `
		INSERT OR IGNORE INTO user_app_access (user_id, app_id, role, created_at)
		VALUES (?, ?, 'member', ?)`
	_, err := s.db.ExecContext(ctx, query, userID, appID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("app store grant access: %w", err)
	}
	return nil
}

// RevokeAccess removes a user's access to an app.
func (s *SQLiteStore) RevokeAccess(ctx context.Context, userID, appID string) error {
	const query = `DELETE FROM user_app_access WHERE user_id = ? AND app_id = ?`
	_, err := s.db.ExecContext(ctx, query, userID, appID)
	if err != nil {
		return fmt.Errorf("app store revoke access: %w", err)
	}
	return nil
}

// HasAccess returns true if the given user has access to the given app.
func (s *SQLiteStore) HasAccess(ctx context.Context, userID, appID string) (bool, error) {
	const query = `
		SELECT COUNT(*) FROM user_app_access WHERE user_id = ? AND app_id = ?`
	var count int
	err := s.db.QueryRowContext(ctx, query, userID, appID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("app store has access: %w", err)
	}
	return count > 0, nil
}

// ListUsersWithAccess returns all access records for users who have access to
// the given app.
func (s *SQLiteStore) ListUsersWithAccess(ctx context.Context, appID string) ([]*UserAccess, error) {
	const query = `
		SELECT user_id, app_id, role, created_at
		FROM user_app_access WHERE app_id = ?
		ORDER BY created_at ASC`

	rows, err := s.db.QueryContext(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("app store list users with access: %w", err)
	}
	defer rows.Close()

	var accesses []*UserAccess
	for rows.Next() {
		var ua UserAccess
		if err := rows.Scan(&ua.UserID, &ua.AppID, &ua.Role, &ua.CreatedAt); err != nil {
			return nil, fmt.Errorf("app store list users with access scan: %w", err)
		}
		accesses = append(accesses, &ua)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("app store list users with access rows: %w", err)
	}
	return accesses, nil
}

// ListAppsForUser returns all apps the given user has access to.
func (s *SQLiteStore) ListAppsForUser(ctx context.Context, userID string) ([]*App, error) {
	const query = `
		SELECT ` + selectAppColumnsAliased + `
		FROM apps a
		INNER JOIN user_app_access uaa ON uaa.app_id = a.id
		WHERE uaa.user_id = ?
		ORDER BY a.name`
	return s.queryApps(ctx, query, userID)
}

// FavoriteIDs returns the app IDs this user has pinned to the top of their
// dashboard.
func (s *SQLiteStore) FavoriteIDs(ctx context.Context, userID string) (map[string]bool, error) {
	const query = `SELECT app_id FROM user_app_access WHERE user_id = ? AND favorite = 1`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("app store favorite ids: %w", err)
	}
	defer rows.Close()

	ids := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("app store favorite ids scan: %w", err)
		}
		ids[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("app store favorite ids rows: %w", err)
	}
	return ids, nil
}

// ToggleFavorite flips the dashboard pin for one user/app pair in a single
// statement, so two taps in flight cannot race into the same state. found is
// false when there is no access row (the app is unknown, or not granted to that
// user) and nothing is written.
func (s *SQLiteStore) ToggleFavorite(ctx context.Context, userID, appID string) (favorite, found bool, err error) {
	const query = `
		UPDATE user_app_access
		SET favorite = CASE favorite WHEN 0 THEN 1 ELSE 0 END
		WHERE user_id = ? AND app_id = ?
		RETURNING favorite`

	var flag int
	err = s.db.QueryRowContext(ctx, query, userID, appID).Scan(&flag)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("app store toggle favorite: %w", err)
	}
	return flag == 1, true, nil
}

// appScanner is satisfied by both *sql.Row and *sql.Rows.
type appScanner interface {
	Scan(dest ...any) error
}

// scanApp scans an app from a row result.
func scanApp(s appScanner) (*App, error) {
	var a App
	var isActive int
	var oauthEnabled int
	var adminOnly int
	var clientID sql.NullString
	var clientSecretHash sql.NullString
	var redirectURIsRaw string
	var scopesRaw string
	var resourcesRaw string
	err := s.Scan(
		&a.ID, &a.Slug, &a.Name, &a.Description, &a.HostPattern, &a.DefaultURL,
		&isActive, &a.SessionDurationHours, &a.CreatedAt, &a.UpdatedAt,
		&clientID, &clientSecretHash, &redirectURIsRaw, &oauthEnabled,
		&scopesRaw, &resourcesRaw,
		&a.RequiredGroup, &a.RequiredRole, &a.AllowedCIDRs, &adminOnly,
		&a.AllowedHours, &a.AllowedDays,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.IsActive = isActive != 0
	a.OAuthEnabled = oauthEnabled != 0
	a.AdminOnly = adminOnly != 0
	a.ClientID = clientID.String
	a.ClientSecretHash = clientSecretHash.String
	a.RedirectURIs = splitLines(redirectURIsRaw)
	a.AllowedScopes = splitLines(scopesRaw)
	a.AllowedResources = splitLines(resourcesRaw)
	return &a, nil
}

// nullableString converts an empty string to a NULL sql.NullString, and a
// non-empty string to a valid sql.NullString. This is used for columns that
// are UNIQUE DEFAULT NULL (client_id, client_secret_hash) so that multiple
// rows with an empty value do not violate the UNIQUE constraint.
func nullableString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// joinLines joins a []string into a newline-separated string for DB storage.
// Redirect URIs and the OAuth scope and resource registries all use it.
func joinLines(values []string) string {
	return strings.Join(values, "\n")
}

// splitLines splits a newline-separated string into a []string, filtering out
// empty strings that arise from an empty DB value.
func splitLines(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "\n")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// boolToInt converts a bool to a SQLite-friendly integer (0 or 1).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// mapAppConstraintError maps UNIQUE constraint failures to typed sentinel errors.
func mapAppConstraintError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") {
		if strings.Contains(msg, "apps.slug") {
			return ErrSlugTaken
		}
	}
	return err
}
