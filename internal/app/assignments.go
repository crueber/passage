package app

import (
	"context"
	"fmt"
	"time"
)

// Assignment queries. Membership is flat: users hold groups and roles
// directly (user_app_groups, user_app_roles), and roles contain groups
// (app_role_groups). Effective groups are resolved at read time.

// AssignGroupToRole adds a group to a role. Both must belong to the same
// app; the check happens in the service layer before calling this.
// Uses INSERT OR IGNORE to be idempotent.
func (s *SQLiteStore) AssignGroupToRole(ctx context.Context, roleID, groupID string) error {
	const query = `INSERT OR IGNORE INTO app_role_groups (role_id, group_id, created_at) VALUES (?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, roleID, groupID, time.Now().UTC()); err != nil {
		return fmt.Errorf("app store assign group to role: %w", err)
	}
	return nil
}

// UnassignGroupFromRole removes a group from a role.
func (s *SQLiteStore) UnassignGroupFromRole(ctx context.Context, roleID, groupID string) error {
	const query = `DELETE FROM app_role_groups WHERE role_id = ? AND group_id = ?`
	if _, err := s.db.ExecContext(ctx, query, roleID, groupID); err != nil {
		return fmt.Errorf("app store unassign group from role: %w", err)
	}
	return nil
}

// ListGroupsForRole returns the groups assigned to a role, ordered by name.
func (s *SQLiteStore) ListGroupsForRole(ctx context.Context, roleID string) ([]*Group, error) {
	const query = `
		SELECT ` + aliasedNamedColumns + ` FROM app_groups g
		JOIN app_role_groups rg ON rg.group_id = g.id
		WHERE rg.role_id = ? ORDER BY g.name`
	rows, err := s.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("app store list groups for role: %w", err)
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.AppID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("app store list groups for role scan: %w", err)
		}
		groups = append(groups, &g)
	}
	return groups, rows.Err()
}

// AssignUserGroup grants a user a direct group within an app.
// Uses INSERT OR IGNORE to be idempotent.
func (s *SQLiteStore) AssignUserGroup(ctx context.Context, userID, appID, groupID string) error {
	const query = `INSERT OR IGNORE INTO user_app_groups (user_id, app_id, group_id, created_at) VALUES (?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, userID, appID, groupID, time.Now().UTC()); err != nil {
		return fmt.Errorf("app store assign user group: %w", err)
	}
	return nil
}

// UnassignUserGroup removes a user's direct group within an app. Inherited
// groups (via roles) are unaffected — they are not stored per user.
func (s *SQLiteStore) UnassignUserGroup(ctx context.Context, userID, appID, groupID string) error {
	const query = `DELETE FROM user_app_groups WHERE user_id = ? AND app_id = ? AND group_id = ?`
	if _, err := s.db.ExecContext(ctx, query, userID, appID, groupID); err != nil {
		return fmt.Errorf("app store unassign user group: %w", err)
	}
	return nil
}

// ListUserDirectGroups returns the groups a user is directly assigned within
// an app, ordered by name. Role-inherited groups are not included.
func (s *SQLiteStore) ListUserDirectGroups(ctx context.Context, userID, appID string) ([]*Group, error) {
	const query = `
		SELECT ` + aliasedNamedColumns + ` FROM app_groups g
		JOIN user_app_groups ug ON ug.group_id = g.id
		WHERE ug.user_id = ? AND ug.app_id = ? ORDER BY g.name`
	return s.queryUserGroups(ctx, query, userID, appID)
}

// ListUserInheritedGroups returns the groups a user inherits through the
// roles they hold within an app, ordered by name. Direct assignments are
// not included.
func (s *SQLiteStore) ListUserInheritedGroups(ctx context.Context, userID, appID string) ([]*Group, error) {
	const query = `
		SELECT DISTINCT ` + aliasedNamedColumns + ` FROM app_groups g
		JOIN app_role_groups rg ON rg.group_id = g.id
		JOIN user_app_roles ur ON ur.role_id = rg.role_id
		WHERE ur.user_id = ? AND ur.app_id = ? ORDER BY g.name`
	return s.queryUserGroups(ctx, query, userID, appID)
}

// queryUserGroups scans group rows from an assignment join query.
func (s *SQLiteStore) queryUserGroups(ctx context.Context, query string, args ...any) ([]*Group, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("app store query user groups: %w", err)
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.AppID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("app store query user groups scan: %w", err)
		}
		groups = append(groups, &g)
	}
	return groups, rows.Err()
}

// AssignUserRole grants a user a role within an app.
// Uses INSERT OR IGNORE to be idempotent.
func (s *SQLiteStore) AssignUserRole(ctx context.Context, userID, appID, roleID string) error {
	const query = `INSERT OR IGNORE INTO user_app_roles (user_id, app_id, role_id, created_at) VALUES (?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, userID, appID, roleID, time.Now().UTC()); err != nil {
		return fmt.Errorf("app store assign user role: %w", err)
	}
	return nil
}

// UnassignUserRole removes a user's role within an app.
func (s *SQLiteStore) UnassignUserRole(ctx context.Context, userID, appID, roleID string) error {
	const query = `DELETE FROM user_app_roles WHERE user_id = ? AND app_id = ? AND role_id = ?`
	if _, err := s.db.ExecContext(ctx, query, userID, appID, roleID); err != nil {
		return fmt.Errorf("app store unassign user role: %w", err)
	}
	return nil
}

// ListUserRoles returns the roles a user holds within an app, ordered by name.
func (s *SQLiteStore) ListUserRoles(ctx context.Context, userID, appID string) ([]*Role, error) {
	const query = `
		SELECT r.id, r.app_id, r.name, r.description, r.created_at, r.updated_at
		FROM app_roles r
		JOIN user_app_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ? AND ur.app_id = ? ORDER BY r.name`
	rows, err := s.db.QueryContext(ctx, query, userID, appID)
	if err != nil {
		return nil, fmt.Errorf("app store list user roles: %w", err)
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		var ro Role
		if err := rows.Scan(&ro.ID, &ro.AppID, &ro.Name, &ro.Description, &ro.CreatedAt, &ro.UpdatedAt); err != nil {
			return nil, fmt.Errorf("app store list user roles scan: %w", err)
		}
		roles = append(roles, &ro)
	}
	return roles, rows.Err()
}

// aliasedNamedColumns mirrors selectNamedColumns with the "g." table alias
// for join queries against app_groups.
const aliasedNamedColumns = `g.id, g.app_id, g.name, g.description, g.created_at, g.updated_at`

// userRoleNames returns the names of the roles a user holds within an app.
func (s *SQLiteStore) UserRoleNames(ctx context.Context, userID, appID string) ([]string, error) {
	const query = `
		SELECT r.name FROM app_roles r
		JOIN user_app_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ? AND ur.app_id = ? ORDER BY r.name`
	return s.stringList(ctx, "user role names", query, userID, appID)
}

// effectiveGroupNames returns the names of a user's effective groups within
// an app: direct groups plus the groups of every role the user holds,
// deduplicated and ordered by name. This is the set embedded in OIDC claims.
func (s *SQLiteStore) EffectiveGroupNames(ctx context.Context, userID, appID string) ([]string, error) {
	const query = `
		SELECT g.name FROM app_groups g
		JOIN user_app_groups ug ON ug.group_id = g.id
		WHERE ug.user_id = ? AND ug.app_id = ?
		UNION
		SELECT g.name FROM app_groups g
		JOIN app_role_groups rg ON rg.group_id = g.id
		JOIN user_app_roles ur ON ur.role_id = rg.role_id
		WHERE ur.user_id = ? AND ur.app_id = ?
		ORDER BY 1`
	return s.stringList(ctx, "effective group names", query, userID, appID, userID, appID)
}

// stringList scans a single text column from a query.
func (s *SQLiteStore) stringList(ctx context.Context, label, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("app store %s: %w", label, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("app store %s scan: %w", label, err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
