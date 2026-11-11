package app

import (
	"context"
	"errors"
	"time"

	"github.com/crueber/passage/internal/policy"
)

// Sentinel errors for app-related operations.
var (
	ErrNotFound           = errors.New("app: not found")
	ErrSlugTaken          = errors.New("app: slug already taken")
	ErrNoAppForHost       = errors.New("app: no registered app matches this host")
	ErrNameTaken          = errors.New("app: a group or role with that name already exists for this app")
	ErrCrossAppAssignment = errors.New("app: role and group belong to different apps")

	ErrOAuthNotEnabled     = errors.New("app: oauth is not enabled for this app")
	ErrInvalidClientSecret = errors.New("app: invalid client secret")
	ErrRedirectURIMismatch = errors.New("app: redirect_uri does not match registered URIs")
)

// Group is a named group scoped to a single app.
type Group struct {
	ID          string
	AppID       string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Role is a named role scoped to a single app.
type Role struct {
	ID          string
	AppID       string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// App represents a downstream application registered with Passage.
type App struct {
	ID          string
	Slug        string
	Name        string
	Description string
	HostPattern string
	DefaultURL  string // empty string means not set
	IsActive    bool
	// SessionDurationHours overrides the global session duration for sessions
	// created for this app. Zero means "use the global default."
	SessionDurationHours int
	CreatedAt            time.Time
	UpdatedAt            time.Time

	// OAuth client fields. Zero values mean OAuth is not enabled for this app.
	ClientID         string
	ClientSecretHash string
	RedirectURIs     []string // stored as newline-separated in DB
	OAuthEnabled     bool

	// AllowedScopes is the app's scope registry. When non-empty, an
	// authorization request may only ask for a subset of these scopes and the
	// granted scope is exactly what was requested. Empty means the client may
	// ask for anything, which is the behaviour before the registry existed.
	AllowedScopes []string // stored as newline-separated in DB
	// AllowedResources is the app's audience registry (RFC 8707). When
	// non-empty, a "resource" parameter must exactly match one of these
	// absolute URIs. Empty means resource indicators are not accepted.
	AllowedResources []string // stored as newline-separated in DB

	// Access policy fields. The zero value of each means "no restriction", so
	// an app with no policy behaves exactly as it did before policies existed.
	// Parsing and evaluation live in internal/policy; see Service.EvaluateAccess.
	RequiredGroup string // one app-scoped group name the user must hold
	RequiredRole  string // one app-scoped role name the user must hold
	AllowedCIDRs  string // comma/space separated CIDR prefixes
	AdminOnly     bool   // only admin users may use the app
	AllowedHours  string // "HH:MM-HH:MM" in server local time
	AllowedDays   string // ISO weekday list/ranges (1 = Monday … 7 = Sunday)
}

// Policy returns the app's access policy in the form internal/policy
// evaluates. A zero-value policy imposes no restriction.
func (a *App) Policy() policy.Policy {
	return policy.Policy{
		RequiredGroup: a.RequiredGroup,
		RequiredRole:  a.RequiredRole,
		AllowedCIDRs:  a.AllowedCIDRs,
		AdminOnly:     a.AdminOnly,
		AllowedHours:  a.AllowedHours,
		AllowedDays:   a.AllowedDays,
	}
}

// UserAccess represents a user's access grant to a specific app.
type UserAccess struct {
	UserID    string
	AppID     string
	Role      string
	CreatedAt time.Time
}

// Store is the persistence interface for apps. It is defined here, at the
// consumer boundary, as per Go convention.
type Store interface {
	Create(ctx context.Context, app *App) error
	GetByID(ctx context.Context, id string) (*App, error)
	GetBySlug(ctx context.Context, slug string) (*App, error)
	GetByClientID(ctx context.Context, clientID string) (*App, error)
	ListActive(ctx context.Context) ([]*App, error)
	List(ctx context.Context) ([]*App, error)
	Update(ctx context.Context, app *App) error
	Delete(ctx context.Context, id string) error
	GrantAccess(ctx context.Context, userID, appID string) error
	RevokeAccess(ctx context.Context, userID, appID string) error
	HasAccess(ctx context.Context, userID, appID string) (bool, error)
	// ListUsersWithAccess returns the access records for all users with access
	// to the given app. It returns []*UserAccess rather than user.User to
	// avoid a cross-package dependency on the user domain type.
	ListUsersWithAccess(ctx context.Context, appID string) ([]*UserAccess, error)
	ListAppsForUser(ctx context.Context, userID string) ([]*App, error)

	// App groups and roles.
	CreateGroup(ctx context.Context, g *Group) error
	GetGroup(ctx context.Context, id string) (*Group, error)
	ListGroupsByApp(ctx context.Context, appID string) ([]*Group, error)
	UpdateGroup(ctx context.Context, g *Group) error
	DeleteGroup(ctx context.Context, id string) error
	CreateRole(ctx context.Context, ro *Role) error
	GetRole(ctx context.Context, id string) (*Role, error)
	ListRolesByApp(ctx context.Context, appID string) ([]*Role, error)
	UpdateRole(ctx context.Context, ro *Role) error
	DeleteRole(ctx context.Context, id string) error

	// Assignments: role→group, user→group, user→role. Effective groups are
	// resolved at read time (direct groups plus groups of held roles).
	AssignGroupToRole(ctx context.Context, roleID, groupID string) error
	UnassignGroupFromRole(ctx context.Context, roleID, groupID string) error
	ListGroupsForRole(ctx context.Context, roleID string) ([]*Group, error)
	AssignUserGroup(ctx context.Context, userID, appID, groupID string) error
	UnassignUserGroup(ctx context.Context, userID, appID, groupID string) error
	ListUserDirectGroups(ctx context.Context, userID, appID string) ([]*Group, error)
	ListUserInheritedGroups(ctx context.Context, userID, appID string) ([]*Group, error)
	AssignUserRole(ctx context.Context, userID, appID, roleID string) error
	UnassignUserRole(ctx context.Context, userID, appID, roleID string) error
	ListUserRoles(ctx context.Context, userID, appID string) ([]*Role, error)
	UserRoleNames(ctx context.Context, userID, appID string) ([]string, error)
	EffectiveGroupNames(ctx context.Context, userID, appID string) ([]string, error)
}

// AccessStore is the persistence interface for user-app access grants. It is
// defined here, at the consumer boundary, as per Go convention.
type AccessStore interface {
	GrantAccess(ctx context.Context, userID, appID string) error
	RevokeAccess(ctx context.Context, userID, appID string) error
	HasAccess(ctx context.Context, userID, appID string) (bool, error)
	// ListUsersWithAccess returns the access records for all users with access
	// to the given app. It returns []*UserAccess rather than user.User to
	// avoid a cross-package dependency on the user domain type.
	ListUsersWithAccess(ctx context.Context, appID string) ([]*UserAccess, error)
	ListAppsForUser(ctx context.Context, userID string) ([]*App, error)
}
