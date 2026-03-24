package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

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
		INSERT INTO apps (id, slug, name, description, host_pattern, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		a.ID, a.Slug, a.Name, a.Description, a.HostPattern,
		boolToInt(a.IsActive), a.CreatedAt, a.UpdatedAt,
	)
	if err != nil {
		return mapAppConstraintError(err)
	}
	return nil
}

// GetByID looks up an app by its UUID.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*App, error) {
	const query = `
		SELECT id, slug, name, description, host_pattern, is_active, created_at, updated_at
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
		SELECT id, slug, name, description, host_pattern, is_active, created_at, updated_at
		FROM apps WHERE slug = ?`
	row := s.db.QueryRowContext(ctx, query, slug)
	a, err := scanApp(row)
	if err != nil {
		return nil, fmt.Errorf("app store get by slug: %w", err)
	}
	return a, nil
}

// ListActive returns all active apps ordered by creation time ascending.
func (s *SQLiteStore) ListActive(ctx context.Context) ([]*App, error) {
	const query = `
		SELECT id, slug, name, description, host_pattern, is_active, created_at, updated_at
		FROM apps WHERE is_active = 1 ORDER BY created_at ASC`
	return s.queryApps(ctx, query)
}

// List returns all apps ordered by name.
func (s *SQLiteStore) List(ctx context.Context) ([]*App, error) {
	const query = `
		SELECT id, slug, name, description, host_pattern, is_active, created_at, updated_at
		FROM apps ORDER BY name`
	return s.queryApps(ctx, query)
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
		SET slug = ?, name = ?, description = ?, host_pattern = ?, is_active = ?, updated_at = ?
		WHERE id = ?`

	res, err := s.db.ExecContext(ctx, query,
		a.Slug, a.Name, a.Description, a.HostPattern,
		boolToInt(a.IsActive), a.UpdatedAt, a.ID,
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
		SELECT a.id, a.slug, a.name, a.description, a.host_pattern, a.is_active, a.created_at, a.updated_at
		FROM apps a
		INNER JOIN user_app_access uaa ON uaa.app_id = a.id
		WHERE uaa.user_id = ?
		ORDER BY a.name`
	return s.queryApps(ctx, query, userID)
}

// appScanner is satisfied by both *sql.Row and *sql.Rows.
type appScanner interface {
	Scan(dest ...any) error
}

// scanApp scans an app from a row result.
func scanApp(s appScanner) (*App, error) {
	var a App
	var isActive int
	err := s.Scan(
		&a.ID, &a.Slug, &a.Name, &a.Description, &a.HostPattern,
		&isActive, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.IsActive = isActive != 0
	return &a, nil
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
