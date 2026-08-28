package app

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// selectNamedColumns is the ordered column list shared by app_groups and
// app_roles. Both tables have identical shape.
const selectNamedColumns = `id, app_id, name, description, created_at, updated_at`

// createNamed inserts a row into the given table with a fresh UUID.
// A UNIQUE(app_id, name) violation maps to ErrNameTaken.
func (s *SQLiteStore) createNamed(ctx context.Context, table string, id, appID, name, description string) error {
	now := time.Now().UTC()
	query := fmt.Sprintf(`
		INSERT INTO %s (id, app_id, name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`, table) // table is a compile-time constant at every callsite.
	_, err := s.db.ExecContext(ctx, query, id, appID, name, description, now, now)
	if err != nil {
		return mapNameConstraintError(err)
	}
	return nil
}

// updateNamed saves name and description changes to an existing row.
func (s *SQLiteStore) updateNamed(ctx context.Context, table, id, name, description string) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET name = ?, description = ?, updated_at = ?
		WHERE id = ?`, table) // table is a compile-time constant at every callsite.
	res, err := s.db.ExecContext(ctx, query, name, description, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("app store update %s: %w", table, mapNameConstraintError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("app store update %s rows affected: %w", table, err)
	}
	if n == 0 {
		return fmt.Errorf("app store update %s: %w", table, ErrNotFound)
	}
	return nil
}

// deleteNamed removes a row by ID.
func (s *SQLiteStore) deleteNamed(ctx context.Context, table, id string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE id = ?`, table) // compile-time constant at every callsite.
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("app store delete %s: %w", table, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("app store delete %s rows affected: %w", table, err)
	}
	if n == 0 {
		return fmt.Errorf("app store delete %s: %w", table, ErrNotFound)
	}
	return nil
}

// listNamed returns all rows of the given table for an app, ordered by name.
func (s *SQLiteStore) listNamed(ctx context.Context, table, appID string) ([]*namedRow, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM %s WHERE app_id = ? ORDER BY name`, selectNamedColumns, table) // compile-time constant at every callsite.
	rows, err := s.db.QueryContext(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("app store list %s: %w", table, err)
	}
	defer rows.Close()

	var out []*namedRow
	for rows.Next() {
		var n namedRow
		if err := rows.Scan(&n.ID, &n.AppID, &n.Name, &n.Description, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, fmt.Errorf("app store list %s scan: %w", table, err)
		}
		out = append(out, &n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("app store list %s rows: %w", table, err)
	}
	return out, nil
}

// getNamed looks up a single row by ID.
func (s *SQLiteStore) getNamed(ctx context.Context, table, id string) (*namedRow, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM %s WHERE id = ?`, selectNamedColumns, table) // compile-time constant at every callsite.
	var n namedRow
	err := s.db.QueryRowContext(ctx, query, id).
		Scan(&n.ID, &n.AppID, &n.Name, &n.Description, &n.CreatedAt, &n.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("app store get %s: %w", table, err)
	}
	return &n, nil
}

// namedRow is the shared row shape of app_groups and app_roles. Typed
// accessors below convert it to Group or Role.
type namedRow struct {
	ID          string
	AppID       string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (n *namedRow) group() *Group {
	return &Group{ID: n.ID, AppID: n.AppID, Name: n.Name, Description: n.Description, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt}
}

func (n *namedRow) role() *Role {
	return &Role{ID: n.ID, AppID: n.AppID, Name: n.Name, Description: n.Description, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt}
}

// ─── Groups ──────────────────────────────────────────────────────────────────

// CreateGroup inserts a new group for an app. A new UUID is assigned to
// g.ID before inserting.
func (s *SQLiteStore) CreateGroup(ctx context.Context, g *Group) error {
	id, err := newUUID()
	if err != nil {
		return fmt.Errorf("app store create group: %w", err)
	}
	g.ID = id
	if err := s.createNamed(ctx, "app_groups", g.ID, g.AppID, g.Name, g.Description); err != nil {
		return fmt.Errorf("app store create group: %w", err)
	}
	return nil
}

// GetGroup looks up a group by its UUID.
func (s *SQLiteStore) GetGroup(ctx context.Context, id string) (*Group, error) {
	n, err := s.getNamed(ctx, "app_groups", id)
	if err != nil {
		return nil, err
	}
	return n.group(), nil
}

// ListGroupsByApp returns all groups for the given app ordered by name.
func (s *SQLiteStore) ListGroupsByApp(ctx context.Context, appID string) ([]*Group, error) {
	rows, err := s.listNamed(ctx, "app_groups", appID)
	if err != nil {
		return nil, err
	}
	groups := make([]*Group, len(rows))
	for i, n := range rows {
		groups[i] = n.group()
	}
	return groups, nil
}

// UpdateGroup saves changes to an existing group.
func (s *SQLiteStore) UpdateGroup(ctx context.Context, g *Group) error {
	return s.updateNamed(ctx, "app_groups", g.ID, g.Name, g.Description)
}

// DeleteGroup removes a group by ID.
func (s *SQLiteStore) DeleteGroup(ctx context.Context, id string) error {
	return s.deleteNamed(ctx, "app_groups", id)
}

// ─── Roles ───────────────────────────────────────────────────────────────────

// CreateRole inserts a new role for an app. A new UUID is assigned to
// ro.ID before inserting.
func (s *SQLiteStore) CreateRole(ctx context.Context, ro *Role) error {
	id, err := newUUID()
	if err != nil {
		return fmt.Errorf("app store create role: %w", err)
	}
	ro.ID = id
	if err := s.createNamed(ctx, "app_roles", ro.ID, ro.AppID, ro.Name, ro.Description); err != nil {
		return fmt.Errorf("app store create role: %w", err)
	}
	return nil
}

// GetRole looks up a role by its UUID.
func (s *SQLiteStore) GetRole(ctx context.Context, id string) (*Role, error) {
	n, err := s.getNamed(ctx, "app_roles", id)
	if err != nil {
		return nil, err
	}
	return n.role(), nil
}

// ListRolesByApp returns all roles for the given app ordered by name.
func (s *SQLiteStore) ListRolesByApp(ctx context.Context, appID string) ([]*Role, error) {
	rows, err := s.listNamed(ctx, "app_roles", appID)
	if err != nil {
		return nil, err
	}
	roles := make([]*Role, len(rows))
	for i, n := range rows {
		roles[i] = n.role()
	}
	return roles, nil
}

// UpdateRole saves changes to an existing role.
func (s *SQLiteStore) UpdateRole(ctx context.Context, ro *Role) error {
	return s.updateNamed(ctx, "app_roles", ro.ID, ro.Name, ro.Description)
}

// DeleteRole removes a role by ID.
func (s *SQLiteStore) DeleteRole(ctx context.Context, id string) error {
	return s.deleteNamed(ctx, "app_roles", id)
}

// mapNameConstraintError maps the UNIQUE(app_id, name) violation on the
// groups/roles tables to the typed ErrNameTaken sentinel.
func mapNameConstraintError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") &&
		(strings.Contains(msg, "app_groups.name") || strings.Contains(msg, "app_roles.name")) {
		return ErrNameTaken
	}
	return err
}
