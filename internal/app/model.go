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

	ErrOAuthNotEnabled     = errors.New("app: oauth is not enabled for this app")
	ErrInvalidClientSecret = errors.New("app: invalid client secret")
	ErrRedirectURIMismatch = errors.New("app: redirect_uri does not match registered URIs")
)

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
