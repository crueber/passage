package admin

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/email"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// Flash represents a flash message rendered above page content.
// This is a local alias so admin templates and user templates share the same field names.
type Flash = user.Flash

// userStore is the minimal interface for direct user CRUD operations.
// Defined at the consumer boundary.
type userStore interface {
	Create(ctx context.Context, u *user.User) error
	GetByID(ctx context.Context, id string) (*user.User, error)
	List(ctx context.Context) ([]*user.User, error)
	Count(ctx context.Context) (int, error)
	Update(ctx context.Context, u *user.User) error
	Delete(ctx context.Context, id string) error
}

// userServiceOps is the minimal interface for service-level user operations.
// Defined at the consumer boundary.
type userServiceOps interface {
	GeneratePasswordReset(ctx context.Context, email string) (string, error)
	// Invitations: an admin offers an account by mail; no users row exists
	// until the recipient accepts.
	CreateInvitation(ctx context.Context, emailAddr, name, invitedBy string, ttl time.Duration) (*user.Invitation, error)
	ListPendingInvitations(ctx context.Context) ([]*user.Invitation, error)
	RevokeInvitation(ctx context.Context, id string) error
}

// appServiceOps is the minimal interface for app management.
// Defined at the consumer boundary.
type appServiceOps interface {
	List(ctx context.Context) ([]*app.App, error)
	Count(ctx context.Context) (int, error)
	GetByID(ctx context.Context, id string) (*app.App, error)
	Create(ctx context.Context, a *app.App) error
	Update(ctx context.Context, a *app.App) error
	Delete(ctx context.Context, id string) error
	ListUsersWithAccess(ctx context.Context, appID string) ([]*app.UserAccess, error)
	ListAppsForUser(ctx context.Context, userID string) ([]*app.App, error)
	GrantAccess(ctx context.Context, userID, appID string) error
	RevokeAccess(ctx context.Context, userID, appID string) error
	GenerateClientCredentials(ctx context.Context, appID string) (clientSecret string, err error)
	RotateClientSecret(ctx context.Context, appID string) (clientSecret string, err error)

	// App groups and roles.
	CreateGroup(ctx context.Context, g *app.Group) error
	GetGroup(ctx context.Context, id string) (*app.Group, error)
	ListGroupsByApp(ctx context.Context, appID string) ([]*app.Group, error)
	ListAllGroups(ctx context.Context) ([]*app.Group, error)
	UpdateGroup(ctx context.Context, g *app.Group) error
	DeleteGroup(ctx context.Context, id string) error
	CreateRole(ctx context.Context, ro *app.Role) error
	GetRole(ctx context.Context, id string) (*app.Role, error)
	ListRolesByApp(ctx context.Context, appID string) ([]*app.Role, error)
	ListAllRoles(ctx context.Context) ([]*app.Role, error)
	UpdateRole(ctx context.Context, ro *app.Role) error
	DeleteRole(ctx context.Context, id string) error

	// Assignments: role→group, user→group, user→role.
	AssignGroupToRole(ctx context.Context, roleID, groupID string) error
	UnassignGroupFromRole(ctx context.Context, roleID, groupID string) error
	ListGroupsForRole(ctx context.Context, roleID string) ([]*app.Group, error)
	ListRoleGroupsByApp(ctx context.Context, appID string) (map[string][]*app.Group, error)
	AssignUserGroup(ctx context.Context, userID, appID, groupID string) error
	UnassignUserGroup(ctx context.Context, userID, appID, groupID string) error
	ListUserDirectGroups(ctx context.Context, userID, appID string) ([]*app.Group, error)
	ListUserInheritedGroups(ctx context.Context, userID, appID string) ([]*app.Group, error)
	AssignUserRole(ctx context.Context, userID, appID, roleID string) error
	UnassignUserRole(ctx context.Context, userID, appID, roleID string) error
	ListUserRoles(ctx context.Context, userID, appID string) ([]*app.Role, error)
	ListUserAssignments(ctx context.Context, userID string) (*app.UserAssignments, error)
}

// sessionServiceOps is the minimal interface for session management.
// Defined at the consumer boundary.
type sessionServiceOps interface {
	ListAll(ctx context.Context) ([]*session.Session, error)
	CountActive(ctx context.Context) (int, error)
	RevokeSessionByPublicID(ctx context.Context, publicID string) error
	RevokeAllByUser(ctx context.Context, userID string) error
}

// credentialCounter is the minimal interface for querying passkey credential counts.
// Defined at the consumer boundary.
type credentialCounter interface {
	CountByUser(ctx context.Context, userID string) (int, error)
}

// authEventRecorder records authentication events for the security log. The
// admin MFA reset is recorded both as an audit event (who did what) and as an
// auth event (it changes how that account signs in). Defined at the consumer
// boundary; backed by *authlog.Recorder in run.go.
type authEventRecorder interface {
	Record(ctx context.Context, e authlog.Event)
}

// mfaAdmin is the admin-facing view of two-factor state: the user-list badge
// and the recovery reset. Defined at the consumer boundary; backed by
// *mfa.Service in run.go.
type mfaAdmin interface {
	ListEnabledIDs(ctx context.Context) ([]string, error)
	Reset(ctx context.Context, userID string) error
}

// auditLogger is the minimal interface for recording admin audit events.
// Defined at the consumer boundary.
type auditLogger interface {
	Log(ctx context.Context, e *AuditEvent)
	List(ctx context.Context, f AuditFilter) ([]*AuditEvent, error)
	Count(ctx context.Context, f AuditFilter) (int, error)
}

// loginThrottleAdmin is the admin-facing view of per-account login throttling.
// Defined at the consumer boundary; backed by *ratelimit.AccountService in run.go.
type loginThrottleAdmin interface {
	ListLocked(ctx context.Context) ([]*ratelimit.AccountState, error)
	Unlock(ctx context.Context, username string) error
}

// Handler holds all admin HTTP handlers in one struct.
type Handler struct {
	userStore    userStore
	userSvc      userServiceOps
	sessions     sessionServiceOps
	apps         appServiceOps
	settings     SettingsStore
	credentials  credentialCounter
	mfa          mfaAdmin
	audit        auditLogger
	authLog      authLogReader
	authRecorder authEventRecorder
	throttle     loginThrottleAdmin
	apiTokens    apiTokenManager
	providers    providerManager
	signingKeys  signingKeyManager
	// settingsReload applies constructor-bound settings (rate limits, lockout)
	// after a save. Optional; nil in tests.
	settingsReload func(ctx context.Context)
	mailer         email.Sender
	tmpl           *template.Template
	cfg            *config.Config
	logger         *slog.Logger
}

// NewHandler creates a new admin Handler with all dependencies wired.
func NewHandler(
	userStore userStore,
	userSvc userServiceOps,
	sessions sessionServiceOps,
	apps appServiceOps,
	settings SettingsStore,
	credentials credentialCounter,
	mfaSvc mfaAdmin,
	mailer email.Sender,
	tmpl *template.Template,
	cfg *config.Config,
	logger *slog.Logger,
	audit auditLogger,
	authLog authLogReader,
	authRecorder authEventRecorder,
	throttle loginThrottleAdmin,
	apiTokens apiTokenManager,
	signingKeys signingKeyManager,
) *Handler {
	return &Handler{
		userStore:    userStore,
		userSvc:      userSvc,
		sessions:     sessions,
		apps:         apps,
		settings:     settings,
		credentials:  credentials,
		mfa:          mfaSvc,
		audit:        audit,
		authLog:      authLog,
		authRecorder: authRecorder,
		throttle:     throttle,
		apiTokens:    apiTokens,
		signingKeys:  signingKeys,
		mailer:       mailer,
		tmpl:         tmpl,
		cfg:          cfg,
		logger:       logger,
	}
}

// SetSettingsReloader wires the callback that re-applies live settings which
// are held by running components (the rate limiters and the lockout service).
func (h *Handler) SetSettingsReloader(fn func(ctx context.Context)) { h.settingsReload = fn }

// Routes registers all admin routes on the given chi.Router.
// The router should already be mounted at /admin and protected by RequireAdmin.
func (h *Handler) Routes(r chi.Router) {
	// Dashboard
	r.Get("/", h.GetDashboard)

	// Users
	r.Get("/users", h.GetUsers)
	r.Get("/users/new", h.GetNewUser)
	r.Post("/users", h.PostCreateUser)
	r.Get("/users/invite", h.GetInviteUser)
	r.Post("/users/invite", h.PostInviteUser)
	r.Post("/users/invitations/{id}/revoke", h.PostRevokeInvitation)
	r.Get("/users/{id}", h.GetEditUser)
	r.Post("/users/{id}", h.PostUpdateUser)
	r.Post("/users/{id}/delete", h.PostDeleteUser)
	r.Post("/users/{id}/reset-password", h.PostResetUserPassword)
	r.Post("/users/{id}/unlock", h.PostUnlockUser)
	r.Post("/users/{id}/reset-mfa", h.PostResetMFA)
	r.Post("/users/{id}/sessions/revoke-all", h.PostRevokeAllUserSessions)
	r.Get("/users/{id}/apps", h.GetUserApps)
	r.Post("/users/{id}/apps", h.PostUserApps)

	// Apps
	r.Get("/apps", h.GetApps)
	r.Get("/apps/new", h.GetNewApp)
	r.Post("/apps", h.PostCreateApp)
	r.Get("/apps/{id}", h.GetEditApp)
	r.Post("/apps/{id}", h.PostUpdateApp)
	r.Get("/apps/{id}/oauth", h.GetAppOAuth)
	r.Post("/apps/{id}/oauth-settings", h.PostAppOAuthSettings)
	r.Get("/apps/{id}/policies", h.GetAppPolicies)
	r.Post("/apps/{id}/policies", h.PostAppPolicies)
	r.Post("/apps/{id}/delete", h.PostDeleteApp)
	r.Post("/apps/{id}/access/{userId}/revoke", h.PostRevokeAccess)
	r.Get("/apps/{id}/access/{userId}/assignments", h.GetAppUserAssignments)
	r.Post("/apps/{id}/access/{userId}/assignments", h.PostAppUserAssignments)
	r.Get("/apps/{id}/groups", h.GetAppGroups)
	r.Post("/apps/{id}/groups", h.PostCreateAppGroup)
	r.Get("/apps/{id}/groups/{gid}/edit", h.GetEditAppGroup)
	r.Post("/apps/{id}/groups/{gid}", h.PostUpdateAppGroup)
	r.Post("/apps/{id}/groups/{gid}/delete", h.PostDeleteAppGroup)
	r.Get("/apps/{id}/roles", h.GetAppRoles)
	r.Post("/apps/{id}/roles", h.PostCreateAppRole)
	r.Get("/apps/{id}/roles/{gid}/edit", h.GetEditAppRole)
	r.Post("/apps/{id}/roles/{gid}", h.PostUpdateAppRole)
	r.Post("/apps/{id}/roles/{gid}/delete", h.PostDeleteAppRole)
	r.Get("/apps/{id}/access", h.GetAppAccess)
	r.Post("/apps/{id}/access", h.PostGrantAccess)
	r.Post("/apps/{id}/oauth/generate", h.PostGenerateOAuthCredentials)
	r.Post("/apps/{id}/oauth/rotate", h.PostRotateOAuthSecret)

	// Sessions
	r.Get("/sessions", h.GetSessions)
	r.Post("/sessions/{id}/revoke", h.PostRevokeSession)

	// Settings
	r.Get("/settings", h.GetSettings)
	r.Post("/settings", h.PostSettings)

	// OIDC signing keys (kid history).
	r.Get("/signing-keys", h.GetSigningKeys)
	r.Post("/signing-keys/rotate", h.PostRotateSigningKey)
	r.Post("/signing-keys/{kid}/retire", h.PostRetireSigningKey)
	r.Post("/signing-keys/{kid}/delete", h.PostDeleteSigningKey)

	// API tokens for the read-only admin REST API (/api/v1).
	r.Get("/api-tokens", h.GetAPITokens)
	r.Post("/api-tokens", h.PostCreateAPIToken)
	r.Post("/api-tokens/{id}/revoke", h.PostRevokeAPIToken)

	// Upstream identity providers.
	r.Get("/providers", h.GetProviders)
	r.Get("/providers/new", h.GetNewProvider)
	r.Post("/providers", h.PostCreateProvider)
	r.Get("/providers/{id}", h.GetEditProvider)
	r.Post("/providers/{id}", h.PostUpdateProvider)
	r.Post("/providers/{id}/delete", h.PostDeleteProvider)

	// Logs (sign-ins and admin actions).
	r.Get("/audit-log", h.redirectLogs(logTabAdmin))
	r.Get("/logs", h.GetLogs)
	r.Get("/security-log", h.redirectLogs(logTabSignins))
}

// ─── base page data ──────────────────────────────────────────────────────────

// basePage is embedded into every admin page data struct.
type basePage struct {
	web.Themed
	ActiveNav string
	UserName  string
	Flash     *Flash
	CSRFToken string
}

// pageTheme returns the signed-in admin's theme override, or "" for the server
// default. The session middleware has already put the user in the context.
func pageTheme(r *http.Request) string {
	if u, ok := session.UserFromContext(r.Context()); ok && u != nil {
		return u.Theme
	}
	return ""
}

// pageUserName returns the name shown in the admin top bar, preferring the
// display name over the username.
func pageUserName(r *http.Request) string {
	if u, ok := session.UserFromContext(r.Context()); ok && u != nil {
		if u.Name != "" {
			return u.Name
		}
		return u.Username
	}
	return ""
}

// base constructs a basePage for the given request, populating the CSRF token
// from the request context (set by csrf.ProtectAuthenticated middleware).
func (h *Handler) base(r *http.Request, nav string) basePage {
	return basePage{
		Themed:    web.NewThemed(pageTheme(r)),
		ActiveNav: nav,
		UserName:  pageUserName(r),
		CSRFToken: csrf.TokenFromContext(r.Context()),
	}
}

// smtpConfigured reports whether the live SMTP settings can send mail.
func (h *Handler) smtpConfigured(ctx context.Context) bool {
	host := strings.TrimSpace(settings.Raw(ctx, h.settings, settings.SMTPHost, h.cfg.SMTP.Host))
	from := strings.TrimSpace(settings.Raw(ctx, h.settings, settings.SMTPFrom, h.cfg.SMTP.From))
	return host != "" && from != ""
}

// baseFlash constructs a basePage with an attached Flash message.
func (h *Handler) baseFlash(r *http.Request, nav string, flash *Flash) basePage {
	return basePage{
		Themed:    web.NewThemed(pageTheme(r)),
		ActiveNav: nav,
		UserName:  pageUserName(r),
		Flash:     flash,
		CSRFToken: csrf.TokenFromContext(r.Context()),
	}
}

// baseQueryFlash constructs a basePage with any flash parsed from ?flash=.
func (h *Handler) baseQueryFlash(r *http.Request, nav string) basePage {
	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}
	return h.baseFlash(r, nav, flash)
}

// flashFromQuery converts a URL query-param flash code into a Flash value.
func flashFromQuery(code string) *Flash {
	switch code {
	case "created":
		return &Flash{Type: "success", Message: "Created successfully."}
	case "updated":
		return &Flash{Type: "success", Message: "Saved successfully."}
	case "deleted":
		return &Flash{Type: "success", Message: "Deleted successfully."}
	case "revoked":
		return &Flash{Type: "success", Message: "Session revoked."}
	case "sessions-revoked":
		return &Flash{Type: "success", Message: "All sessions revoked."}
	case "reset-sent":
		return &Flash{Type: "success", Message: "Password reset email sent."}
	case "invited":
		return &Flash{Type: "success", Message: "Invitation sent. No account exists until the recipient accepts."}
	case "invite-revoked":
		return &Flash{Type: "success", Message: "Invitation revoked. The link no longer works."}
	case "unlocked":
		return &Flash{Type: "success", Message: "Account unlocked."}
	case "mfa-reset":
		return &Flash{Type: "success", Message: "Two-factor authentication reset. The user can sign in with their password and enrol again."}
	case "api-token-revoked":
		return &Flash{Type: "success", Message: "API token revoked. Requests using it will fail from now on."}
	case "key-rotated":
		return &Flash{Type: "success", Message: "New signing key generated and made current. Existing id_tokens keep verifying until they expire."}
	case "key-retired":
		return &Flash{Type: "success", Message: "Signing key retired. It is no longer served in the JWKS and its id_tokens are no longer accepted."}
	case "key-deleted":
		return &Flash{Type: "success", Message: "Retired signing key deleted."}
	case "access-granted":
		return &Flash{Type: "success", Message: "Access granted."}
	case "access-revoked":
		return &Flash{Type: "success", Message: "Access revoked."}
	case "self-delete-forbidden":
		return &Flash{Type: "error", Message: "You cannot delete your own account."}
	case "delete-has-audit":
		return &Flash{Type: "error", Message: "This user has audit log history and cannot be deleted. Deactivate the account instead."}
	case "error":
		return &Flash{Type: "error", Message: "An error occurred. Please try again."}
	default:
		return nil
	}
}

// ─── render and URL helpers ──────────────────────────────────────────────────

// render executes a named template, buffering output to avoid partial writes.
func (h *Handler) render(w http.ResponseWriter, _ *http.Request, name string, data any) {
	web.Render(w, h.tmpl, h.logger, name, data)
}

// baseURL returns the configured server base URL with any trailing slash removed.
// This ensures endpoint URLs constructed in templates are always well-formed.
func (h *Handler) baseURL() string {
	return strings.TrimRight(h.cfg.Server.BaseURL, "/")
}

// publicBaseURL returns the configured base URL, falling back to the incoming
// request's scheme and host when server.base_url is unset (development only).
func (h *Handler) publicBaseURL(r *http.Request) string {
	if base := h.baseURL(); base != "" {
		return base
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// logAudit records an admin audit event. It extracts the acting user from the
// request context and the client IP from the request. Errors are non-fatal.
func (h *Handler) logAudit(r *http.Request, action, targetType, targetID, targetName string) {
	actorID := ""
	actorName := ""
	if u, ok := session.UserFromContext(r.Context()); ok {
		actorID = u.ID
		actorName = u.Username
	}

	h.audit.Log(r.Context(), &AuditEvent{
		ActorID:    actorID,
		ActorName:  actorName,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		TargetName: targetName,
		IPAddress:  web.ClientIP(r),
	})
}
