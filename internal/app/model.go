package app

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors for app-related operations.
var (
	ErrNotFound     = errors.New("app: not found")
	ErrSlugTaken    = errors.New("app: slug already taken")
	ErrNoAppForHost = errors.New("app: no registered app matches this host")
	ErrNameTaken    = errors.New("app: a group or role with that name already exists for this app")

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
