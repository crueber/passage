package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Service implements business logic for app management and host resolution.
type Service struct {
	store  Store
	access AccessStore
	logger *slog.Logger
}

// NewService creates a new Service with the given dependencies.
func NewService(store Store, access AccessStore, logger *slog.Logger) *Service {
	return &Service{
		store:  store,
		access: access,
		logger: logger,
	}
}

// ResolveFromHost resolves the app registered for the given host. The host
// may include a port suffix which is stripped before matching. It iterates
// all active apps and returns the first one whose HostPattern matches using
// path.Match semantics. Returns ErrNoAppForHost if no app matches.
func (s *Service) ResolveFromHost(ctx context.Context, host string) (*App, error) {
	// Strip port if present (e.g. "grafana.home.example.com:443" → "grafana.home.example.com").
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	apps, err := s.store.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve from host list apps: %w", err)
	}

	var matched *App
	var matchCount int
	for _, a := range apps {
		ok, err := path.Match(a.HostPattern, host)
		if err != nil {
			// path.Match only returns an error for malformed patterns.
			s.logger.Warn("app host pattern is malformed", "app_id", a.ID, "slug", a.Slug, "pattern", a.HostPattern, "error", err)
			continue
		}
		if ok {
			matchCount++
			if matched == nil {
				matched = a
			}
		}
	}

	if matched == nil {
		return nil, ErrNoAppForHost
	}

	if matchCount > 1 {
		// Log a warning but proceed with the first match by creation date
		// (ListActive already orders by created_at ASC, so matched is correct).
		s.logger.Warn("multiple apps match the same host; using earliest-created match",
			"host", host, "match_count", matchCount, "app_id", matched.ID, "slug", matched.Slug)
	}

	return matched, nil
}

// ValidateHostPattern checks if the given pattern overlaps with any existing
// app's pattern (excluding the app identified by excludeID, for edit flows).
// It logs a warning on overlap but always returns nil — it is advisory only.
func (s *Service) ValidateHostPattern(ctx context.Context, pattern, excludeID string) error {
	apps, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("validate host pattern list apps: %w", err)
	}

	for _, a := range apps {
		if a.ID == excludeID {
			continue
		}
		if a.HostPattern == "" || pattern == "" {
			continue
		}
		// Check for overlap between the new pattern and the existing one.
		// We use path.Match in both directions as a heuristic:
		//   - If the existing pattern (used as a path.Match glob) matches the new
		//     pattern's literal string, they overlap (e.g. "*.a.com" matches "foo.a.com").
		//   - If the new pattern (used as a glob) matches the existing pattern's literal
		//     string, they also overlap.
		//
		// Limitation: two wildcard patterns with overlapping match sets are NOT detected
		// here if neither literally matches the other's pattern string
		// (e.g. "*.home.a.com" vs "*.a.com" — the broader wildcard will match real hosts
		// that the narrower one also matches, but neither glob string is matched by the
		// other). Log a warning for the cases we can detect so the admin is aware.
		overlap := false
		if strings.EqualFold(a.HostPattern, pattern) {
			overlap = true
		}
		if !overlap {
			// Check if either pattern is a wildcard that could match the other's
			// non-wildcard prefix. e.g. "*.home.example.com" vs "foo.home.example.com".
			// Generate a synthetic test hostname from the non-wildcard pattern.
			if !strings.Contains(a.HostPattern, "*") {
				if ok, _ := path.Match(pattern, a.HostPattern); ok {
					overlap = true
				}
			}
			if !overlap && !strings.Contains(pattern, "*") {
				if ok, _ := path.Match(a.HostPattern, pattern); ok {
					overlap = true
				}
			}
		}
		if overlap {
			s.logger.Warn("new host_pattern overlaps with existing app",
				"new_pattern", pattern, "existing_app_id", a.ID, "existing_slug", a.Slug, "existing_pattern", a.HostPattern)
		}
	}
	return nil
}

// Create generates a UUID, sets timestamps, and persists a new app.
func (s *Service) Create(ctx context.Context, a *App) error {
	if err := s.store.Create(ctx, a); err != nil {
		return fmt.Errorf("app service create: %w", err)
	}
	return nil
}

// GetByID returns the app with the given UUID.
func (s *Service) GetByID(ctx context.Context, id string) (*App, error) {
	a, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("app service get by id: %w", err)
	}
	return a, nil
}

// GetBySlug returns the app with the given slug.
func (s *Service) GetBySlug(ctx context.Context, slug string) (*App, error) {
	a, err := s.store.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("app service get by slug: %w", err)
	}
	return a, nil
}

// List returns all apps.
func (s *Service) List(ctx context.Context) ([]*App, error) {
	apps, err := s.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("app service list: %w", err)
	}
	return apps, nil
}

// Update saves changes to an existing app.
func (s *Service) Update(ctx context.Context, a *App) error {
	if err := s.store.Update(ctx, a); err != nil {
		return fmt.Errorf("app service update: %w", err)
	}
	return nil
}

// Delete removes an app by ID.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("app service delete: %w", err)
	}
	return nil
}

// GrantAccess grants a user access to an app.
func (s *Service) GrantAccess(ctx context.Context, userID, appID string) error {
	if err := s.access.GrantAccess(ctx, userID, appID); err != nil {
		return fmt.Errorf("app service grant access: %w", err)
	}
	return nil
}

// RevokeAccess removes a user's access to an app.
func (s *Service) RevokeAccess(ctx context.Context, userID, appID string) error {
	if err := s.access.RevokeAccess(ctx, userID, appID); err != nil {
		return fmt.Errorf("app service revoke access: %w", err)
	}
	return nil
}

// HasAccess returns true if the given user has access to the given app.
func (s *Service) HasAccess(ctx context.Context, userID, appID string) (bool, error) {
	ok, err := s.access.HasAccess(ctx, userID, appID)
	if err != nil {
		return false, fmt.Errorf("app service has access: %w", err)
	}
	return ok, nil
}

// ListUsersWithAccess returns all access records for users who have access to
// the given app.
func (s *Service) ListUsersWithAccess(ctx context.Context, appID string) ([]*UserAccess, error) {
	accesses, err := s.access.ListUsersWithAccess(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("app service list users with access: %w", err)
	}
	return accesses, nil
}

// ListAppsForUser returns all apps the given user has access to.
func (s *Service) ListAppsForUser(ctx context.Context, userID string) ([]*App, error) {
	apps, err := s.access.ListAppsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("app service list apps for user: %w", err)
	}
	return apps, nil
}

// GenerateClientCredentials sets a client_id (equal to the app's slug),
// generates a new random 32-byte client secret, bcrypt-hashes it (cost 12),
// stores the hash, enables OAuth for the app, and returns the plaintext secret.
// The plaintext secret is shown only once and not stored.
func (s *Service) GenerateClientCredentials(ctx context.Context, appID string) (string, error) {
	a, err := s.store.GetByID(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("app service generate client credentials get app: %w", err)
	}

	if a.OAuthEnabled && a.ClientID != "" {
		return "", fmt.Errorf("app service generate client credentials: oauth already enabled, use RotateClientSecret to rotate the secret")
	}

	secret, hash, err := generateSecretAndHash()
	if err != nil {
		return "", fmt.Errorf("app service generate client credentials: %w", err)
	}

	a.ClientID = a.Slug
	a.ClientSecretHash = hash
	a.OAuthEnabled = true

	if err := s.store.Update(ctx, a); err != nil {
		return "", fmt.Errorf("app service generate client credentials update: %w", err)
	}
	return secret, nil
}

// RotateClientSecret generates a new random 32-byte client secret, bcrypt-hashes
// it (cost 12), stores the hash, and returns the plaintext secret.
// The plaintext secret is shown only once and not stored.
func (s *Service) RotateClientSecret(ctx context.Context, appID string) (string, error) {
	a, err := s.store.GetByID(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("app service rotate client secret get app: %w", err)
	}

	if !a.OAuthEnabled || a.ClientID == "" {
		return "", fmt.Errorf("app service rotate client secret: %w", ErrOAuthNotEnabled)
	}

	secret, hash, err := generateSecretAndHash()
	if err != nil {
		return "", fmt.Errorf("app service rotate client secret: %w", err)
	}

	a.ClientSecretHash = hash

	if err := s.store.Update(ctx, a); err != nil {
		return "", fmt.Errorf("app service rotate client secret update: %w", err)
	}
	return secret, nil
}

// generateSecretAndHash generates a cryptographically random 32-byte secret
// encoded as a hex string, bcrypt-hashes it at cost 12, and returns both.
func generateSecretAndHash() (plaintext, hash string, err error) {
	var raw [32]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return "", "", fmt.Errorf("generate random secret: %w", err)
	}
	plaintext = hex.EncodeToString(raw[:])

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(plaintext), 12)
	if err != nil {
		return "", "", fmt.Errorf("bcrypt hash secret: %w", err)
	}
	return plaintext, string(hashBytes), nil
}

// ─── App groups and roles ────────────────────────────────────────────────────

// CreateGroup generates a UUID and persists a new group for the app.
func (s *Service) CreateGroup(ctx context.Context, g *Group) error {
	return s.store.CreateGroup(ctx, g)
}

// GetGroup returns the group with the given UUID.
func (s *Service) GetGroup(ctx context.Context, id string) (*Group, error) {
	return s.store.GetGroup(ctx, id)
}

// ListGroupsByApp returns all groups for the given app ordered by name.
func (s *Service) ListGroupsByApp(ctx context.Context, appID string) ([]*Group, error) {
	return s.store.ListGroupsByApp(ctx, appID)
}

// UpdateGroup saves changes to an existing group.
func (s *Service) UpdateGroup(ctx context.Context, g *Group) error {
	return s.store.UpdateGroup(ctx, g)
}

// DeleteGroup removes a group by ID.
func (s *Service) DeleteGroup(ctx context.Context, id string) error {
	return s.store.DeleteGroup(ctx, id)
}

// CreateRole generates a UUID and persists a new role for the app.
func (s *Service) CreateRole(ctx context.Context, ro *Role) error {
	return s.store.CreateRole(ctx, ro)
}

// GetRole returns the role with the given UUID.
func (s *Service) GetRole(ctx context.Context, id string) (*Role, error) {
	return s.store.GetRole(ctx, id)
}

// ListRolesByApp returns all roles for the given app ordered by name.
func (s *Service) ListRolesByApp(ctx context.Context, appID string) ([]*Role, error) {
	return s.store.ListRolesByApp(ctx, appID)
}

// UpdateRole saves changes to an existing role.
func (s *Service) UpdateRole(ctx context.Context, ro *Role) error {
	return s.store.UpdateRole(ctx, ro)
}

// DeleteRole removes a role by ID.
func (s *Service) DeleteRole(ctx context.Context, id string) error {
	return s.store.DeleteRole(ctx, id)
}

// ─── Assignments ─────────────────────────────────────────────────────────────

// AssignGroupToRole adds a group to a role. Both must belong to the same app.
// Idempotent.
func (s *Service) AssignGroupToRole(ctx context.Context, roleID, groupID string) error {
	ro, err := s.store.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	g, err := s.store.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if ro.AppID != g.AppID {
		return ErrCrossAppAssignment
	}
	return s.store.AssignGroupToRole(ctx, roleID, groupID)
}

// UnassignGroupFromRole removes a group from a role.
func (s *Service) UnassignGroupFromRole(ctx context.Context, roleID, groupID string) error {
	return s.store.UnassignGroupFromRole(ctx, roleID, groupID)
}

// ListGroupsForRole returns the groups assigned to a role.
func (s *Service) ListGroupsForRole(ctx context.Context, roleID string) ([]*Group, error) {
	return s.store.ListGroupsForRole(ctx, roleID)
}

// AssignUserGroup grants a user a direct group within an app. Idempotent.
func (s *Service) AssignUserGroup(ctx context.Context, userID, appID, groupID string) error {
	return s.store.AssignUserGroup(ctx, userID, appID, groupID)
}

// UnassignUserGroup removes a user's direct group within an app.
func (s *Service) UnassignUserGroup(ctx context.Context, userID, appID, groupID string) error {
	return s.store.UnassignUserGroup(ctx, userID, appID, groupID)
}

// ListUserDirectGroups returns a user's directly assigned groups for an app.
func (s *Service) ListUserDirectGroups(ctx context.Context, userID, appID string) ([]*Group, error) {
	return s.store.ListUserDirectGroups(ctx, userID, appID)
}

// ListUserInheritedGroups returns the groups a user inherits through held
// roles for an app. These are never stored per user and cannot be revoked
// individually.
func (s *Service) ListUserInheritedGroups(ctx context.Context, userID, appID string) ([]*Group, error) {
	return s.store.ListUserInheritedGroups(ctx, userID, appID)
}

// AssignUserRole grants a user a role within an app. Idempotent.
func (s *Service) AssignUserRole(ctx context.Context, userID, appID, roleID string) error {
	return s.store.AssignUserRole(ctx, userID, appID, roleID)
}

// UnassignUserRole removes a user's role within an app.
func (s *Service) UnassignUserRole(ctx context.Context, userID, appID, roleID string) error {
	return s.store.UnassignUserRole(ctx, userID, appID, roleID)
}

// ListUserRoles returns the roles a user holds for an app.
func (s *Service) ListUserRoles(ctx context.Context, userID, appID string) ([]*Role, error) {
	return s.store.ListUserRoles(ctx, userID, appID)
}

// TokenAssignments returns the names of a user's roles and their effective
// groups (direct plus role-inherited) within an app, for embedding in OIDC
// token claims. Both lists are deduplicated and ordered by name.
func (s *Service) TokenAssignments(ctx context.Context, userID, appID string) (roles, groups []string, err error) {
	if roles, err = s.store.UserRoleNames(ctx, userID, appID); err != nil {
		return nil, nil, fmt.Errorf("app service token assignments roles: %w", err)
	}
	if groups, err = s.store.EffectiveGroupNames(ctx, userID, appID); err != nil {
		return nil, nil, fmt.Errorf("app service token assignments groups: %w", err)
	}
	// Normalize to empty slices so the JSON claims are [] rather than null
	// when the user has no assignments.
	if roles == nil {
		roles = []string{}
	}
	if groups == nil {
		groups = []string{}
	}
	return roles, groups, nil
}

// GetByClientID returns the app with the given OAuth client_id.
func (s *Service) GetByClientID(ctx context.Context, clientID string) (*App, error) {
	return s.store.GetByClientID(ctx, clientID)
}
