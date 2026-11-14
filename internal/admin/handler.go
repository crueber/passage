package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/email"
	"github.com/crueber/passage/internal/policy"
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
	Update(ctx context.Context, u *user.User) error
	Delete(ctx context.Context, id string) error
}

// userServiceOps is the minimal interface for service-level user operations.
// Defined at the consumer boundary.
type userServiceOps interface {
	ChangePassword(ctx context.Context, userID, newPassword string) error
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
	UpdateGroup(ctx context.Context, g *app.Group) error
	DeleteGroup(ctx context.Context, id string) error
	CreateRole(ctx context.Context, ro *app.Role) error
	GetRole(ctx context.Context, id string) (*app.Role, error)
	ListRolesByApp(ctx context.Context, appID string) ([]*app.Role, error)
	UpdateRole(ctx context.Context, ro *app.Role) error
	DeleteRole(ctx context.Context, id string) error

	// Assignments: role→group, user→group, user→role.
	AssignGroupToRole(ctx context.Context, roleID, groupID string) error
	UnassignGroupFromRole(ctx context.Context, roleID, groupID string) error
	ListGroupsForRole(ctx context.Context, roleID string) ([]*app.Group, error)
	AssignUserGroup(ctx context.Context, userID, appID, groupID string) error
	UnassignUserGroup(ctx context.Context, userID, appID, groupID string) error
	ListUserDirectGroups(ctx context.Context, userID, appID string) ([]*app.Group, error)
	ListUserInheritedGroups(ctx context.Context, userID, appID string) ([]*app.Group, error)
	AssignUserRole(ctx context.Context, userID, appID, roleID string) error
	UnassignUserRole(ctx context.Context, userID, appID, roleID string) error
	ListUserRoles(ctx context.Context, userID, appID string) ([]*app.Role, error)
}

// sessionServiceOps is the minimal interface for session management.
// Defined at the consumer boundary.
type sessionServiceOps interface {
	ListAll(ctx context.Context) ([]*session.Session, error)
	RevokeSession(ctx context.Context, token string) error
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

	// Audit log
	r.Get("/audit-log", h.redirectLogs(logTabAdmin))

	// Authentication events (logins, logouts, passkey, magic link)
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
	host := settings.String(ctx, h.settings, settings.SMTPHost, h.cfg.SMTP.Host)
	from := settings.String(ctx, h.settings, settings.SMTPFrom, h.cfg.SMTP.From)
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
	case "error":
		return &Flash{Type: "error", Message: "An error occurred. Please try again."}
	default:
		return nil
	}
}

// ─── render helper ───────────────────────────────────────────────────────────

// render executes a named template, buffering output to avoid partial writes.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.Error("admin: render template", "name", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// baseURL returns the configured server base URL with any trailing slash removed.
// This ensures endpoint URLs constructed in templates are always well-formed.
func (h *Handler) baseURL() string {
	return strings.TrimRight(h.cfg.Server.BaseURL, "/")
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

type dashboardData struct {
	basePage
	UserCount    int
	AppCount     int
	SessionCount int
	// Recent is the newest handful of authentication events, so the landing
	// page answers "did that sign-in arrive?" without opening the log.
	Recent []*authlog.Event
}

// GetDashboard renders the admin dashboard with summary counts.
func (h *Handler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := h.userStore.List(ctx)
	if err != nil {
		h.logger.Error("admin: dashboard list users", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	apps, err := h.apps.List(ctx)
	if err != nil {
		h.logger.Error("admin: dashboard list apps", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	sessions, err := h.sessions.ListAll(ctx)
	if err != nil {
		h.logger.Error("admin: dashboard list sessions", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// A failure to read recent events must not take down the dashboard; the
	// counts are still useful on their own.
	recent, err := h.authLog.List(ctx, authlog.Filter{Limit: 8})
	if err != nil {
		h.logger.Warn("admin: dashboard recent events", "error", err)
		recent = nil
	}

	h.render(w, r, "admin-dashboard", dashboardData{
		basePage:     h.base(r, "dashboard"),
		UserCount:    len(users),
		AppCount:     len(apps),
		SessionCount: len(sessions),
		Recent:       recent,
	})
}

// ─── Users ───────────────────────────────────────────────────────────────────

type usersData struct {
	basePage
	Users  []*user.User
	Pager  pagination
	locked map[string]bool // lower-cased username -> currently locked
	// mfaEnabled is user ID -> has a completed TOTP enrollment. Keyed by ID
	// because usernames are user-editable and IDs are not.
	mfaEnabled map[string]bool
}

// IsLocked reports whether username has an active login lock. Templates cannot
// lower-case, so the lookup normalises here.
func (d usersData) IsLocked(username string) bool {
	return d.locked[strings.ToLower(strings.TrimSpace(username))]
}

// MFAEnabled reports whether the user has two-factor authentication enabled.
func (d usersData) MFAEnabled(userID string) bool {
	return d.mfaEnabled[userID]
}

// GetUsers renders the user list page.
func (h *Handler) GetUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := h.userStore.List(ctx)
	if err != nil {
		h.logger.Error("admin: list users", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// One query for the whole page, not one per row. A throttle failure must
	// not take down the user list: render it without badges and log.
	locked := make(map[string]bool)
	if h.throttle != nil {
		states, err := h.throttle.ListLocked(ctx)
		if err != nil {
			h.logger.Warn("admin: list locked accounts", "error", err)
		} else {
			for _, state := range states {
				locked[strings.ToLower(state.Username)] = true
			}
		}
	}

	// One query for the whole page. A failure here must not hide the user
	// list: render without MFA badges and log.
	mfaEnabled := make(map[string]bool)
	if h.mfa != nil {
		ids, err := h.mfa.ListEnabledIDs(ctx)
		if err != nil {
			h.logger.Warn("admin: list users with MFA", "error", err)
		} else {
			for _, id := range ids {
				mfaEnabled[id] = true
			}
		}
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	pager := parsePagination("/admin/users", r.URL.Query(), "page", "per_page", len(users))
	h.render(w, r, "admin-users", usersData{
		basePage:   h.baseFlash(r, "users", flash),
		Users:      pageItems(users, pager),
		Pager:      pager,
		locked:     locked,
		mfaEnabled: mfaEnabled,
	})
}

type userFormData struct {
	basePage
	EditUser     *user.User
	IsNew        bool
	PasskeyCount int
}

// GetNewUser renders the new user form.
func (h *Handler) GetNewUser(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin-user-form", userFormData{
		basePage: h.base(r, "users"),
		IsNew:    true,
	})
}

// PostCreateUser handles admin user creation, bypassing allow_registration.
func (h *Handler) PostCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: "Invalid form submission."}),
			IsNew:    true,
		})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	emailAddr := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	password := r.FormValue("password")
	isAdmin := r.FormValue("is_admin") == "on"
	isActive := r.FormValue("is_active") == "on"

	if username == "" || emailAddr == "" || len(password) < 8 {
		msg := "Username, email and password (min 8 chars) are required."
		if len(password) > 0 && len(password) < 8 {
			msg = "Password must be at least 8 characters."
		}
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			IsNew:    true,
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), settings.Int(r.Context(), h.settings, settings.BcryptCost, h.cfg.Auth.BcryptCost, 10, 31))
	if err != nil {
		h.logger.Error("admin: hash password", "error", err)
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: "Internal error. Please try again."}),
			IsNew:    true,
		})
		return
	}

	u := &user.User{
		Username:     username,
		Email:        emailAddr,
		Name:         name,
		PasswordHash: string(hash),
		IsAdmin:      isAdmin,
		IsActive:     isActive,
		Roles:        "[]",
	}

	if err := h.userStore.Create(r.Context(), u); err != nil {
		msg := "Failed to create user."
		if errors.Is(err, user.ErrUsernameTaken) {
			msg = "That username is already taken."
		} else if errors.Is(err, user.ErrEmailTaken) {
			msg = "An account with that email already exists."
		}
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			IsNew:    true,
		})
		return
	}

	h.logAudit(r, AuditActionUserCreate, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=created", http.StatusFound)
}

// Invitation expiry bounds for the admin form. A link that lives too long is
// an unauthenticated path into the instance; a shorter one is easy to outlive
// an inbox check.
const (
	invitationExpiryDaysDefault = 7
	invitationExpiryDaysMax     = 30
)

// inviteUserData is the render data for the invite form and the pending list.
type inviteUserData struct {
	basePage
	Invitations    []*user.Invitation
	Email          string
	Name           string
	ExpiryDays     int
	SMTPConfigured bool
}

// GetInviteUser renders the invitation form and the list of pending invites.
func (h *Handler) GetInviteUser(w http.ResponseWriter, r *http.Request) {
	invitations, err := h.userSvc.ListPendingInvitations(r.Context())
	if err != nil {
		// The form is still useful without the list; a query failure must not
		// block the page.
		h.logger.Warn("admin: list pending invitations", "error", err)
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-invite-user", inviteUserData{
		basePage:       h.baseFlash(r, "users", flash),
		Invitations:    invitations,
		ExpiryDays:     invitationExpiryDaysDefault,
		SMTPConfigured: h.smtpConfigured(r.Context()),
	})
}

// PostInviteUser creates an invitation and emails the link. It deliberately
// writes no user row: the account is created when the recipient accepts.
func (h *Handler) PostInviteUser(w http.ResponseWriter, r *http.Request) {
	renderErr := func(msg, emailAddr, name string, days int) {
		pending, err := h.userSvc.ListPendingInvitations(r.Context())
		if err != nil {
			h.logger.Warn("admin: list pending invitations", "error", err)
		}
		h.render(w, r, "admin-invite-user", inviteUserData{
			basePage:       h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			Invitations:    pending,
			Email:          emailAddr,
			Name:           name,
			ExpiryDays:     days,
			SMTPConfigured: h.smtpConfigured(r.Context()),
		})
	}

	if err := r.ParseForm(); err != nil {
		renderErr("Invalid form submission.", "", "", invitationExpiryDaysDefault)
		return
	}

	emailAddr := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	days, err := strconv.Atoi(strings.TrimSpace(r.FormValue("expiry_days")))
	if err != nil || days < 1 || days > invitationExpiryDaysMax {
		renderErr(fmt.Sprintf("Expiry must be a whole number of days between 1 and %d.", invitationExpiryDaysMax), emailAddr, name, invitationExpiryDaysDefault)
		return
	}
	if emailAddr == "" || !strings.Contains(emailAddr, "@") {
		renderErr("Enter a valid email address.", emailAddr, name, days)
		return
	}
	if !h.smtpConfigured(r.Context()) {
		renderErr("Invitations are sent by email, so SMTP must be configured first (Settings → Email).", emailAddr, name, days)
		return
	}

	invitedBy := ""
	if actingUser, ok := session.UserFromContext(r.Context()); ok && actingUser != nil {
		invitedBy = actingUser.Name
		if invitedBy == "" {
			invitedBy = actingUser.Username
		}
	}

	ttl := time.Duration(days) * 24 * time.Hour
	inv, err := h.userSvc.CreateInvitation(r.Context(), emailAddr, name, invitedBy, ttl)
	if err != nil {
		msg := "Could not create the invitation. Please try again."
		switch {
		case errors.Is(err, user.ErrEmailTaken):
			msg = "An account with that email already exists."
		case errors.Is(err, user.ErrEmailRequired):
			msg = "Enter a valid email address."
		case errors.Is(err, user.ErrSMTPNotConfigured):
			msg = "Invitations are sent by email, so SMTP must be configured first (Settings → Email)."
		default:
			h.logger.Error("admin: create invitation", "email", emailAddr, "error", err)
		}
		renderErr(msg, emailAddr, name, days)
		return
	}

	baseURL := h.baseURL()
	if baseURL == "" {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		baseURL = scheme + "://" + r.Host
	}
	inviteURL := baseURL + "/invite/" + inv.Token

	if err := h.mailer.SendInvite(r.Context(), inv.Email, inv.Name, invitedBy, inviteURL, ttl); err != nil {
		// No mail means no usable invitation: remove the row so a retry does
		// not silently replace a link nobody received.
		h.logger.Warn("admin: send invitation email", "invitation_id", inv.ID, "error", err)
		if revokeErr := h.userSvc.RevokeInvitation(r.Context(), inv.ID); revokeErr != nil {
			h.logger.Error("admin: revoke unsent invitation", "invitation_id", inv.ID, "error", revokeErr)
		}
		renderErr("Could not send the invitation email. Check the SMTP settings and try again.", emailAddr, name, days)
		return
	}

	h.logAudit(r, AuditActionUserInvite, "invitation", inv.ID, inv.Email)
	http.Redirect(w, r, "/admin/users/invite?flash=invited", http.StatusFound)
}

// PostRevokeInvitation deletes a pending invitation, invalidating its link.
func (h *Handler) PostRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.userSvc.RevokeInvitation(r.Context(), id); err != nil {
		if errors.Is(err, user.ErrInvitationNotFound) {
			http.Redirect(w, r, "/admin/users/invite", http.StatusFound)
			return
		}
		h.logger.Error("admin: revoke invitation", "invitation_id", id, "error", err)
		http.Redirect(w, r, "/admin/users/invite?flash=error", http.StatusFound)
		return
	}

	h.logAudit(r, AuditActionUserInviteRevoke, "invitation", id, "")
	http.Redirect(w, r, "/admin/users/invite?flash=invite-revoked", http.StatusFound)
}

// GetEditUser renders the edit user form.
func (h *Handler) GetEditUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for edit", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	passkeyCount, err := h.credentials.CountByUser(r.Context(), id)
	if err != nil {
		// Non-fatal: log and continue with zero count.
		h.logger.Warn("admin: count passkeys for user", "id", id, "error", err)
	}

	h.render(w, r, "admin-user-form", userFormData{
		basePage:     h.base(r, "users"),
		EditUser:     u,
		IsNew:        false,
		PasskeyCount: passkeyCount,
	})
}

// PostUpdateUser handles saving changes to an existing user.
func (h *Handler) PostUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s", id), http.StatusFound)
		return
	}

	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for update", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	u.Username = strings.TrimSpace(r.FormValue("username"))
	u.Email = strings.TrimSpace(r.FormValue("email"))
	u.Name = strings.TrimSpace(r.FormValue("name"))
	u.IsAdmin = r.FormValue("is_admin") == "on"
	u.IsActive = r.FormValue("is_active") == "on"

	if u.Username == "" || u.Email == "" {
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: "Username and email are required."}),
			EditUser: u,
			IsNew:    false,
		})
		return
	}

	if err := h.userStore.Update(r.Context(), u); err != nil {
		msg := "Failed to update user."
		if errors.Is(err, user.ErrUsernameTaken) {
			msg = "That username is already taken."
		} else if errors.Is(err, user.ErrEmailTaken) {
			msg = "An account with that email already exists."
		}
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			EditUser: u,
			IsNew:    false,
		})
		return
	}

	// If the user was deactivated, revoke all their active sessions immediately.
	if !u.IsActive {
		if err := h.sessions.RevokeAllByUser(r.Context(), u.ID); err != nil {
			h.logger.Warn("admin: revoke sessions for deactivated user", "user_id", u.ID, "error", err)
		}
	}

	h.logAudit(r, AuditActionUserUpdate, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=updated", http.StatusFound)
}

// PostDeleteUser deletes a user by ID.
// An admin cannot delete their own account to prevent self-lockout.
func (h *Handler) PostDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Guard: prevent an admin from deleting their own account.
	if actingUser, ok := session.UserFromContext(r.Context()); ok && actingUser.ID == id {
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s?flash=self-delete-forbidden", id), http.StatusFound)
		return
	}

	// Fetch the user before deletion to capture the username for the audit log.
	target, fetchErr := h.userStore.GetByID(r.Context(), id)

	if err := h.userStore.Delete(r.Context(), id); err != nil && !errors.Is(err, user.ErrNotFound) {
		h.logger.Error("admin: delete user", "id", id, "error", err)
		http.Redirect(w, r, "/admin/users", http.StatusFound)
		return
	}

	username := id
	if fetchErr == nil && target != nil {
		username = target.Username
	}
	h.logAudit(r, AuditActionUserDelete, "user", id, username)
	http.Redirect(w, r, "/admin/users?flash=deleted", http.StatusFound)
}

// PostResetUserPassword generates a password reset token and sends the email.
func (h *Handler) PostResetUserPassword(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for password reset", "id", id, "error", err)
		http.Redirect(w, r, "/admin/users", http.StatusFound)
		return
	}

	token, err := h.userSvc.GeneratePasswordReset(r.Context(), u.Email)
	if err != nil {
		h.logger.Error("admin: generate password reset", "id", id, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s", id), http.StatusFound)
		return
	}

	if token != "" {
		baseURL := h.cfg.Server.BaseURL
		if baseURL == "" {
			scheme := "https"
			if r.TLS == nil {
				scheme = "http"
			}
			baseURL = scheme + "://" + r.Host
		}
		resetURL := baseURL + "/reset/" + token
		if err := h.mailer.SendPasswordReset(r.Context(), u.Email, u.Name, resetURL); err != nil {
			h.logger.Warn("admin: send password reset email", "error", err, "user_id", id)
		}
	}

	h.logAudit(r, AuditActionUserPasswordReset, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=reset-sent", http.StatusFound)
}

// PostUnlockUser clears a per-account login lock and records an audit entry.
// The lock is temporary on its own; this is the operator's "let them back in
// now" action.
func (h *Handler) PostUnlockUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for unlock", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if h.throttle != nil {
		if err := h.throttle.Unlock(r.Context(), u.Username); err != nil {
			h.logger.Error("admin: unlock user", "user_id", id, "error", err)
			http.Redirect(w, r, "/admin/users?flash=error", http.StatusFound)
			return
		}
	}

	h.logAudit(r, AuditActionUserUnlock, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=unlocked", http.StatusFound)
}

// PostResetMFA removes a user's two-factor authentication and recovery codes so
// a second admin can recover an account whose device is lost. It is the
// supported alternative to deleting rows from SQLite by hand.
//
// Deliberately not self-service: a signed-in user disables their own MFA from
// the Security page, with the current password.
func (h *Handler) PostResetMFA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for MFA reset", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if h.mfa != nil {
		if err := h.mfa.Reset(r.Context(), u.ID); err != nil {
			h.logger.Error("admin: reset MFA", "user_id", u.ID, "error", err)
			http.Redirect(w, r, "/admin/users?flash=error", http.StatusFound)
			return
		}
	}

	if h.authRecorder != nil {
		h.authRecorder.Record(r.Context(), authlog.Event{
			Event:     authlog.EventMFAReset,
			Outcome:   authlog.OutcomeSuccess,
			UserID:    u.ID,
			Username:  u.Username,
			IP:        authlog.ClientIP(r),
			UserAgent: r.UserAgent(),
			Detail:    "admin reset",
		})
	}

	h.logAudit(r, AuditActionUserMFAReset, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=mfa-reset", http.StatusFound)
}

// PostRevokeAllUserSessions revokes all active sessions for a user.
// This is a non-destructive operation — the user account is not modified.
func (h *Handler) PostRevokeAllUserSessions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.sessions.RevokeAllByUser(r.Context(), id); err != nil {
		h.logger.Error("admin: revoke all sessions for user", "user_id", id, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s?flash=error", id), http.StatusFound)
		return
	}

	// Best-effort fetch for audit target_name.
	username := id
	if u, err := h.userStore.GetByID(r.Context(), id); err == nil {
		username = u.Username
	}
	h.logAudit(r, AuditActionSessionRevokeAll, "user", id, username)
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%s?flash=sessions-revoked", id), http.StatusFound)
}

// GetUserApps renders the user app access management page.
func (h *Handler) GetUserApps(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	u, err := h.userStore.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for app access", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	allApps, err := h.apps.List(ctx)
	if err != nil {
		h.logger.Error("admin: list apps for user access page", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	userApps, err := h.apps.ListAppsForUser(ctx, id)
	if err != nil {
		h.logger.Error("admin: list apps for user", "user_id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	accessMap := make(map[string]bool, len(userApps))
	for _, a := range userApps {
		accessMap[a.ID] = true
	}

	appsWithAccess := make([]appWithAccess, len(allApps))
	for i, a := range allApps {
		groups, roles, err := h.userAppAssignmentOptions(ctx, id, a.ID)
		if err != nil {
			h.logger.Error("admin: build assignment options for user apps page", "user_id", id, "app_id", a.ID, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		appsWithAccess[i] = appWithAccess{App: a, HasAccess: accessMap[a.ID], Groups: groups, Roles: roles}
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-user-apps", userAppsData{
		basePage:       h.baseFlash(r, "users", flash),
		EditUser:       u,
		AppsWithAccess: appsWithAccess,
	})
}

// PostUserApps handles bulk grant/revoke of app access plus group and
// role assignments for a user, in one save.
func (h *Handler) PostUserApps(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s/apps", id), http.StatusFound)
		return
	}

	_, err := h.userStore.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for post app access", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Build desired set from submitted checkboxes.
	desiredSet := make(map[string]bool, len(r.Form["app_id"]))
	for _, appID := range r.Form["app_id"] {
		desiredSet[appID] = true
	}

	// Build current set from what the user already has access to.
	currentApps, err := h.apps.ListAppsForUser(ctx, id)
	if err != nil {
		h.logger.Error("admin: list apps for user (post)", "user_id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	currentSet := make(map[string]bool, len(currentApps))
	for _, a := range currentApps {
		currentSet[a.ID] = true
	}

	// Iterate over all apps to determine what to grant or revoke.
	allApps, err := h.apps.List(ctx)
	if err != nil {
		h.logger.Error("admin: list all apps for post user access", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	for _, a := range allApps {
		inDesired := desiredSet[a.ID]
		inCurrent := currentSet[a.ID]

		if inDesired && !inCurrent {
			if err := h.apps.GrantAccess(ctx, id, a.ID); err != nil {
				h.logger.Error("admin: grant access (bulk)", "user_id", id, "app_id", a.ID, "error", err)
			}
		} else if !inDesired && inCurrent {
			if err := h.apps.RevokeAccess(ctx, id, a.ID); err != nil {
				h.logger.Error("admin: revoke access (bulk)", "user_id", id, "app_id", a.ID, "error", err)
			}
		}

		// Role and group diffs apply to every app row: the submitted
		// checkboxes reflect what the admin sees, so a save clears
		// assignments even when access is being revoked.
		desiredRoles := toIDSet(r.Form["roles."+a.ID])

		currentRoles, err := h.apps.ListUserRoles(ctx, id, a.ID)
		if err != nil {
			h.logger.Error("admin: list user roles (bulk)", "user_id", id, "app_id", a.ID, "error", err)
			continue
		}
		for _, ro := range currentRoles {
			if !desiredRoles[ro.ID] {
				if err := h.apps.UnassignUserRole(ctx, id, a.ID, ro.ID); err != nil {
					h.logger.Error("admin: unassign user role (bulk)", "user_id", id, "app_id", a.ID, "role_id", ro.ID, "error", err)
				}
			}
		}
		for rid := range desiredRoles {
			if err := h.apps.AssignUserRole(ctx, id, a.ID, rid); err != nil {
				h.logger.Error("admin: assign user role (bulk)", "user_id", id, "app_id", a.ID, "role_id", rid, "error", err)
			}
		}

		// Diff direct groups. Role-inherited groups are excluded from the
		// unassign side: their checkboxes render disabled and are not
		// submitted, so the guard protects their direct assignment.
		inheritedGroups, err := h.apps.ListUserInheritedGroups(ctx, id, a.ID)
		if err != nil {
			h.logger.Error("admin: list inherited groups (bulk)", "user_id", id, "app_id", a.ID, "error", err)
			continue
		}
		inheritedSet := make(map[string]bool, len(inheritedGroups))
		for _, g := range inheritedGroups {
			inheritedSet[g.ID] = true
		}
		desiredGroups := toIDSet(r.Form["groups."+a.ID])
		currentGroups, err := h.apps.ListUserDirectGroups(ctx, id, a.ID)
		if err != nil {
			h.logger.Error("admin: list user groups (bulk)", "user_id", id, "app_id", a.ID, "error", err)
			continue
		}
		for _, g := range currentGroups {
			if !desiredGroups[g.ID] && !inheritedSet[g.ID] {
				if err := h.apps.UnassignUserGroup(ctx, id, a.ID, g.ID); err != nil {
					h.logger.Error("admin: unassign user group (bulk)", "user_id", id, "app_id", a.ID, "group_id", g.ID, "error", err)
				}
			}
		}
		for gid := range desiredGroups {
			if err := h.apps.AssignUserGroup(ctx, id, a.ID, gid); err != nil {
				h.logger.Error("admin: assign user group (bulk)", "user_id", id, "app_id", a.ID, "group_id", gid, "error", err)
			}
		}
	}

	// No success flash: the updated checkbox state is the feedback.
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%s/apps", id), http.StatusFound)
}

// userAppAssignmentOptions builds the checkbox state for one app row on
// the user apps page: the app's groups and roles with the user's current
// membership marked. Groups granted via a held role are marked Inherited.
func (h *Handler) userAppAssignmentOptions(ctx context.Context, userID, appID string) ([]assignmentOption, []assignmentOption, error) {
	allGroups, err := h.apps.ListGroupsByApp(ctx, appID)
	if err != nil {
		return nil, nil, err
	}
	allRoles, err := h.apps.ListRolesByApp(ctx, appID)
	if err != nil {
		return nil, nil, err
	}
	directGroups, err := h.apps.ListUserDirectGroups(ctx, userID, appID)
	if err != nil {
		return nil, nil, err
	}
	inheritedGroups, err := h.apps.ListUserInheritedGroups(ctx, userID, appID)
	if err != nil {
		return nil, nil, err
	}
	userRoles, err := h.apps.ListUserRoles(ctx, userID, appID)
	if err != nil {
		return nil, nil, err
	}

	directSet := make(map[string]bool, len(directGroups))
	for _, g := range directGroups {
		directSet[g.ID] = true
	}
	inheritedSet := make(map[string]bool, len(inheritedGroups))
	for _, g := range inheritedGroups {
		inheritedSet[g.ID] = true
	}
	roleSet := make(map[string]bool, len(userRoles))
	for _, ro := range userRoles {
		roleSet[ro.ID] = true
	}

	groups := make([]assignmentOption, len(allGroups))
	for i, g := range allGroups {
		groups[i] = assignmentOption{
			ID:          g.ID,
			Name:        g.Name,
			Description: g.Description,
			Assigned:    directSet[g.ID],
			Inherited:   inheritedSet[g.ID],
		}
	}
	roles := make([]assignmentOption, len(allRoles))
	for i, ro := range allRoles {
		roles[i] = assignmentOption{
			ID:          ro.ID,
			Name:        ro.Name,
			Description: ro.Description,
			Assigned:    roleSet[ro.ID],
		}
	}
	return groups, roles, nil
}

// ─── Apps ────────────────────────────────────────────────────────────────────

type appsData struct {
	basePage
	Apps  []*app.App
	Pager pagination
}

// GetApps renders the app list page.
func (h *Handler) GetApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.apps.List(r.Context())
	if err != nil {
		h.logger.Error("admin: list apps", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	pager := parsePagination("/admin/apps", r.URL.Query(), "page", "per_page", len(apps))
	h.render(w, r, "admin-apps", appsData{
		basePage: h.baseFlash(r, "apps", flash),
		Apps:     pageItems(apps, pager),
		Pager:    pager,
	})
}

// appTabs carries tab-navigation state for app sub-pages (details, OAuth,
// access, groups, roles, policies).
type appTabs struct {
	App       *app.App
	ActiveTab string // "details", "oauth", "access", "groups", "roles" or "policies"
}

type appFormData struct {
	basePage
	appTabs
	EditApp         *app.App
	IsNew           bool
	NewClientSecret string // non-empty only when just generated or rotated; shown once
	BaseURL         string // used to render OIDC endpoint hints in the template
}

// GetNewApp renders the new app form.
func (h *Handler) GetNewApp(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin-app-form", appFormData{
		basePage: h.base(r, "apps"),
		IsNew:    true,
	})
}

// applyAppPolicy copies the nested access-policy inputs from the submitted app
// form onto a. Values are trimmed but not validated here; callers run
// policy.Validate so a malformed rule re-renders the form instead of being
// saved (Evaluate also fails closed if one ever slips through).
func applyAppPolicy(r *http.Request, a *app.App) {
	a.RequiredGroup = strings.TrimSpace(r.FormValue("required_group"))
	a.RequiredRole = strings.TrimSpace(r.FormValue("required_role"))
	a.AllowedCIDRs = strings.TrimSpace(r.FormValue("allowed_cidrs"))
	a.AdminOnly = r.FormValue("admin_only") == "on"
	a.AllowedHours = strings.TrimSpace(r.FormValue("allowed_hours"))
	a.AllowedDays = strings.TrimSpace(r.FormValue("allowed_days"))
}

// formLines splits a one-value-per-line textarea, trimming whitespace and
// dropping blank lines.
func formLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// applyOAuthRegistry copies the app's scope and audience registries from the
// form and validates them. An empty registry means "no restriction", so an app
// that leaves both textareas blank keeps the pre-registry behaviour.
func applyOAuthRegistry(r *http.Request, a *app.App) error {
	a.AllowedScopes = formLines(r.FormValue("scopes"))
	a.AllowedResources = formLines(r.FormValue("resources"))

	var errs []error
	if err := app.ValidateAllowedScopes(a.AllowedScopes); err != nil {
		errs = append(errs, err)
	}
	if err := app.ValidateAllowedResources(a.AllowedResources); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// oauthRegistryFlashMessage turns a joined registry validation error into one
// line for the form's error flash (errors.Join separates with newlines).
func oauthRegistryFlashMessage(err error) string {
	return "OAuth registry: " + strings.ReplaceAll(err.Error(), "\n", "; ")
}

// policyFlashMessage turns a joined policy validation error into one line for
// the form's error flash (errors.Join separates with newlines).
func policyFlashMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), "policy: ")
	return "Access policy: " + strings.ReplaceAll(msg, "\npolicy: ", "; ")
}

// PostCreateApp handles app creation.
func (h *Handler) PostCreateApp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Invalid form submission."}),
			IsNew:    true,
		})
		return
	}

	a := &app.App{
		Slug:        strings.TrimSpace(r.FormValue("slug")),
		Name:        strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")),
		HostPattern: strings.TrimSpace(r.FormValue("host_pattern")),
		DefaultURL:  strings.TrimSpace(r.FormValue("default_url")),
		IsActive:    r.FormValue("is_active") == "on",
	}

	if a.Slug == "" || a.Name == "" {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Slug and name are required."}),
			EditApp:  a,
			IsNew:    true,
		})
		return
	}

	if a.DefaultURL != "" && !strings.HasPrefix(a.DefaultURL, "http://") && !strings.HasPrefix(a.DefaultURL, "https://") {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Default URL must start with http:// or https://."}),
			EditApp:  a,
			IsNew:    true,
		})
		return
	}

	if _, err := path.Match(a.HostPattern, "test.example.com"); err != nil {
		// path.Match only returns an error for syntactically malformed patterns.
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Host pattern is malformed: " + err.Error()}),
			EditApp:  a,
			IsNew:    true,
		})
		return
	}

	if err := h.apps.Create(r.Context(), a); err != nil {
		msg := "Failed to create app."
		if errors.Is(err, app.ErrSlugTaken) {
			msg = "An app with that slug already exists."
		}
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			EditApp:  a,
			IsNew:    true,
		})
		return
	}

	h.logAudit(r, AuditActionAppCreate, "app", a.ID, a.Name)
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s?flash=created", a.ID), http.StatusFound)
}

// GetEditApp renders the app details tab.
func (h *Handler) GetEditApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for edit", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-app-form", appFormData{
		basePage: h.baseFlash(r, "apps", flash),
		appTabs:  appTabs{App: a, ActiveTab: "details"},
		EditApp:  a,
		IsNew:    false,
	})
}

// GetAppOAuth renders the app OAuth tab.
func (h *Handler) GetAppOAuth(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for oauth tab", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-app-oauth", appFormData{
		basePage: h.baseFlash(r, "apps", flash),
		appTabs:  appTabs{App: a, ActiveTab: "oauth"},
		EditApp:  a,
		IsNew:    false,
		BaseURL:  h.baseURL(),
	})
}

// GetAppPolicies renders the optional access-policy tab.
func (h *Handler) GetAppPolicies(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for policies tab", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-app-policies", appFormData{
		basePage: h.baseFlash(r, "apps", flash),
		appTabs:  appTabs{App: a, ActiveTab: "policies"},
		EditApp:  a,
		IsNew:    false,
	})
}

// PostAppPolicies saves only the optional access-policy fields, so saving the
// Details tab can never rewrite a policy (and vice versa).
func (h *Handler) PostAppPolicies(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/policies", id), http.StatusFound)
		return
	}

	a, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for policy update", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	applyAppPolicy(r, a)
	if err := policy.Validate(a.Policy()); err != nil {
		h.render(w, r, "admin-app-policies", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: policyFlashMessage(err)}),
			appTabs:  appTabs{App: a, ActiveTab: "policies"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	if err := h.apps.Update(r.Context(), a); err != nil {
		h.logger.Error("admin: update app policies", "id", id, "error", err)
		h.render(w, r, "admin-app-policies", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Failed to save policies."}),
			appTabs:  appTabs{App: a, ActiveTab: "policies"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	h.logAudit(r, AuditActionAppUpdate, "app", a.ID, a.Name)
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/policies?flash=updated", id), http.StatusFound)
}

// parseAppSessionDuration reads the optional per-app OAuth session lifetime.
func parseAppSessionDuration(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.FormValue("session_duration_hours"))
	if raw == "" || raw == "0" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 8760 {
		return 0, errors.New("Session duration must be a whole number between 0 and 8760 (0 = use the global default).")
	}
	return n, nil
}

// PostAppOAuthSettings saves the OAuth-only settings (session lifetime and the
// scope/audience registries) without touching the core Details fields.
func (h *Handler) PostAppOAuthSettings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/oauth", id), http.StatusFound)
		return
	}

	a, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for oauth settings", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	renderErr := func(msg string) {
		h.render(w, r, "admin-app-oauth", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			appTabs:  appTabs{App: a, ActiveTab: "oauth"},
			EditApp:  a,
			IsNew:    false,
			BaseURL:  h.baseURL(),
		})
	}

	if err := applyOAuthRegistry(r, a); err != nil {
		renderErr(oauthRegistryFlashMessage(err))
		return
	}
	duration, err := parseAppSessionDuration(r)
	if err != nil {
		renderErr(err.Error())
		return
	}
	a.SessionDurationHours = duration

	if err := h.apps.Update(r.Context(), a); err != nil {
		h.logger.Error("admin: update app oauth settings", "id", id, "error", err)
		renderErr("Failed to save OAuth settings.")
		return
	}

	h.logAudit(r, AuditActionAppUpdate, "app", a.ID, a.Name)
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/oauth?flash=updated", id), http.StatusFound)
}

// PostUpdateApp saves changes to an existing app.
func (h *Handler) PostUpdateApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s", id), http.StatusFound)
		return
	}

	a, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for update", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	a.Slug = strings.TrimSpace(r.FormValue("slug"))
	a.Name = strings.TrimSpace(r.FormValue("name"))
	a.Description = strings.TrimSpace(r.FormValue("description"))
	a.HostPattern = strings.TrimSpace(r.FormValue("host_pattern"))
	a.DefaultURL = strings.TrimSpace(r.FormValue("default_url"))
	a.IsActive = r.FormValue("is_active") == "on"

	// Parse redirect_uris from textarea (one per line, trim whitespace, drop blanks).
	rawURIs := r.FormValue("redirect_uris")
	var uris []string
	for _, line := range strings.Split(rawURIs, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			uris = append(uris, line)
		}
	}
	a.RedirectURIs = uris

	if a.Slug == "" || a.Name == "" {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Slug and name are required."}),
			appTabs:  appTabs{App: a, ActiveTab: "details"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	if a.DefaultURL != "" && !strings.HasPrefix(a.DefaultURL, "http://") && !strings.HasPrefix(a.DefaultURL, "https://") {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Default URL must start with http:// or https://."}),
			appTabs:  appTabs{App: a, ActiveTab: "details"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	if _, err := path.Match(a.HostPattern, "test.example.com"); err != nil {
		// path.Match only returns an error for syntactically malformed patterns.
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Host pattern is malformed: " + err.Error()}),
			appTabs:  appTabs{App: a, ActiveTab: "details"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	if err := h.apps.Update(r.Context(), a); err != nil {
		msg := "Failed to update app."
		if errors.Is(err, app.ErrSlugTaken) {
			msg = "An app with that slug already exists."
		}
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			appTabs:  appTabs{App: a, ActiveTab: "details"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	h.logAudit(r, AuditActionAppUpdate, "app", a.ID, a.Name)
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s?flash=updated", id), http.StatusFound)
}

// PostDeleteApp deletes an app by ID.
func (h *Handler) PostDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Fetch the app before deletion to capture the slug for the audit log.
	target, fetchErr := h.apps.GetByID(r.Context(), id)

	if err := h.apps.Delete(r.Context(), id); err != nil && !errors.Is(err, app.ErrNotFound) {
		h.logger.Error("admin: delete app", "id", id, "error", err)
		http.Redirect(w, r, "/admin/apps?flash=error", http.StatusFound)
		return
	}

	slug := id
	if fetchErr == nil && target != nil {
		slug = target.Slug
	}
	h.logAudit(r, AuditActionAppDelete, "app", id, slug)
	http.Redirect(w, r, "/admin/apps?flash=deleted", http.StatusFound)
}

// PostGenerateOAuthCredentials enables OAuth for an app and generates its
// initial client_id and client_secret. The plaintext secret is shown once in
// the form; it is not stored.
func (h *Handler) PostGenerateOAuthCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	a, err := h.apps.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for oauth generate", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	secret, err := h.apps.GenerateClientCredentials(ctx, id)
	if err != nil {
		msg := "Failed to generate OAuth credentials."
		h.render(w, r, "admin-app-oauth", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			appTabs:  appTabs{App: a, ActiveTab: "oauth"},
			EditApp:  a,
			BaseURL:  h.baseURL(),
		})
		return
	}

	// Re-fetch to get the updated ClientID and OAuthEnabled flag.
	updatedApp, refetchErr := h.apps.GetByID(ctx, id)
	if refetchErr != nil {
		h.logger.Error("admin: re-fetch app after oauth generate", "id", id, "error", refetchErr)
		// Write succeeded — continue rendering with stale app data + new secret
	} else {
		a = updatedApp
	}

	h.logAudit(r, AuditActionOAuthGenerate, "app", a.ID, a.Name)
	h.render(w, r, "admin-app-oauth", appFormData{
		basePage:        h.baseFlash(r, "apps", &Flash{Type: "success", Message: "OAuth credentials generated. Copy the secret — it will not be shown again."}),
		appTabs:         appTabs{App: a, ActiveTab: "oauth"},
		EditApp:         a,
		NewClientSecret: secret,
		BaseURL:         h.baseURL(),
	})
}

// PostRotateOAuthSecret rotates the client secret for an OAuth-enabled app.
// The new plaintext secret is shown once in the form; it is not stored.
func (h *Handler) PostRotateOAuthSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	a, err := h.apps.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for oauth rotate", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	secret, err := h.apps.RotateClientSecret(ctx, id)
	if err != nil {
		msg := "Failed to rotate OAuth client secret."
		h.render(w, r, "admin-app-oauth", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			appTabs:  appTabs{App: a, ActiveTab: "oauth"},
			EditApp:  a,
			BaseURL:  h.baseURL(),
		})
		return
	}

	// Re-fetch to get the updated state.
	updatedApp, refetchErr := h.apps.GetByID(ctx, id)
	if refetchErr != nil {
		h.logger.Error("admin: re-fetch app after oauth rotate", "id", id, "error", refetchErr)
		// Write succeeded — continue rendering with stale app data + new secret
	} else {
		a = updatedApp
	}

	h.logAudit(r, AuditActionOAuthRotate, "app", a.ID, a.Name)
	h.render(w, r, "admin-app-oauth", appFormData{
		basePage:        h.baseFlash(r, "apps", &Flash{Type: "success", Message: "OAuth client secret rotated. Copy the new secret — it will not be shown again."}),
		appTabs:         appTabs{App: a, ActiveTab: "oauth"},
		EditApp:         a,
		NewClientSecret: secret,
		BaseURL:         h.baseURL(),
	})
}

// ─── App Access ───────────────────────────────────────────────────────────────

// userWithAccess bundles a user.User with its UserAccess record for template rendering.
type userWithAccess struct {
	User   *user.User
	Access *app.UserAccess
}

type appAccessData struct {
	basePage
	appTabs
	UsersWithAccess    []userWithAccess
	UsersWithoutAccess []*user.User
	WithPager          pagination
	WithoutPager       pagination
}

// appWithAccess bundles an app with whether the given user has access,
// plus the checkbox state for the app's groups and roles so access and
// assignments can be managed in one save.
type appWithAccess struct {
	App       *app.App
	HasAccess bool
	Groups    []assignmentOption
	Roles     []assignmentOption
}

// userAppsData is the template data for the user app access page.
type userAppsData struct {
	basePage
	EditUser       *user.User
	AppsWithAccess []appWithAccess
}

// loadAppAccessData loads the app plus its with/without-access user lists and
// builds the appAccessData for the access page. Shared by the page render and
// the htmx out-of-band refresh after revoke.
func (h *Handler) loadAppAccessData(r *http.Request, appID string, flash *Flash, q url.Values) (*appAccessData, error) {
	ctx := r.Context()

	a, err := h.apps.GetByID(ctx, appID)
	if err != nil {
		return nil, err
	}

	accesses, err := h.apps.ListUsersWithAccess(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("list users with access: %w", err)
	}

	allUsers, err := h.userStore.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users for access page: %w", err)
	}

	// Build a set of user IDs that have access.
	accessMap := make(map[string]*app.UserAccess, len(accesses))
	for _, ac := range accesses {
		accessMap[ac.UserID] = ac
	}

	// Build user objects for users with access.
	userMap := make(map[string]*user.User, len(allUsers))
	for _, u := range allUsers {
		userMap[u.ID] = u
	}

	var withAccess []userWithAccess
	for _, ac := range accesses {
		if u, ok := userMap[ac.UserID]; ok {
			withAccess = append(withAccess, userWithAccess{User: u, Access: ac})
		}
	}

	var withoutAccess []*user.User
	for _, u := range allUsers {
		if _, ok := accessMap[u.ID]; !ok {
			withoutAccess = append(withoutAccess, u)
		}
	}

	basePath := fmt.Sprintf("/admin/apps/%s/access", appID)
	withPager := parsePagination(basePath, q, "with_page", "per_page", len(withAccess))
	withoutPager := parsePagination(basePath, q, "without_page", "per_page", len(withoutAccess))

	return &appAccessData{
		basePage:           h.baseFlash(r, "apps", flash),
		appTabs:            appTabs{App: a, ActiveTab: "access"},
		UsersWithAccess:    pageItems(withAccess, withPager),
		UsersWithoutAccess: pageItems(withoutAccess, withoutPager),
		WithPager:          withPager,
		WithoutPager:       withoutPager,
	}, nil
}

// GetAppAccess renders the app access management page.
func (h *Handler) GetAppAccess(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	data, err := h.loadAppAccessData(r, id, flash, r.URL.Query())
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app access page", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.render(w, r, "admin-app-access", data)
}

// paginationQuery carries the access list's page state through a grant or
// revoke POST, so the operator stays on the page they acted from.
func paginationQuery(r *http.Request) url.Values {
	q := url.Values{}
	for _, key := range []string{"per_page", "with_page", "without_page"} {
		if v := strings.TrimSpace(r.FormValue(key)); v != "" {
			q.Set(key, v)
		}
	}
	return q
}

func appAccessURL(appID string, q url.Values) string {
	base := fmt.Sprintf("/admin/apps/%s/access", appID)
	if len(q) == 0 {
		return base
	}
	return base + "?" + q.Encode()
}

// PostGrantAccess grants a user access to an app.
func (h *Handler) PostGrantAccess(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/access", appID), http.StatusFound)
		return
	}

	userID := r.FormValue("user_id")
	if userID == "" {
		http.Redirect(w, r, appAccessURL(appID, paginationQuery(r)), http.StatusFound)
		return
	}

	if err := h.apps.GrantAccess(r.Context(), userID, appID); err != nil {
		h.logger.Error("admin: grant access", "user_id", userID, "app_id", appID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/access?flash=error", appID), http.StatusFound)
		return
	}

	// Best-effort fetch for audit target_name.
	appName := appID
	if a, err := h.apps.GetByID(r.Context(), appID); err == nil {
		appName = a.Name
	}
	h.logAudit(r, AuditActionAppGrantAccess, "app", appID, appName)
	// No success flash: the user's move between the tables is the feedback.
	http.Redirect(w, r, appAccessURL(appID, paginationQuery(r)), http.StatusFound)
}

// PostRevokeAccess revokes a user's access to an app.
func (h *Handler) PostRevokeAccess(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "userId")
	_ = r.ParseForm()

	q := paginationQuery(r)
	redirectURL := appAccessURL(appID, q)

	if err := h.apps.RevokeAccess(r.Context(), userID, appID); err != nil {
		h.logger.Error("admin: revoke access", "user_id", userID, "app_id", appID, "error", err)
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", redirectURL)
			return
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Best-effort fetch for audit target_name.
	appName := appID
	if a, err := h.apps.GetByID(r.Context(), appID); err == nil {
		appName = a.Name
	}
	h.logAudit(r, AuditActionAppRevokeAccess, "app", appID, appName)
	// No-JS fallback: full redirect re-renders both sections.
	if r.Header.Get("HX-Request") != "true" {
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// htmx: out-of-band refresh of both tables so the revoked user moves
	// from "Users with access" to "Users without access" without a full
	// page reload. The revoke form swaps its own row away via hx-swap="delete".
	data, err := h.loadAppAccessData(r, appID, nil, q)
	if err != nil {
		h.logger.Error("admin: revoke access oob reload", "app_id", appID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, "admin-app-access-revoke-oob", data); err != nil {
		h.logger.Error("admin: render revoke oob", "app_id", appID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// ─── Sessions ────────────────────────────────────────────────────────────────

// sessionRow bundles a session with its user's username for display.
type sessionRow struct {
	Session  *session.Session
	Username string
	// Device is the parsed "Browser on Platform" label, so the admin table is
	// scannable; the raw user agent stays available as a tooltip.
	Device string
}

type sessionsData struct {
	basePage
	Sessions []sessionRow
}

// GetSessions renders the active sessions list.
func (h *Handler) GetSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessions, err := h.sessions.ListAll(ctx)
	if err != nil {
		h.logger.Error("admin: list sessions", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Load all users to build a username map.
	users, err := h.userStore.List(ctx)
	if err != nil {
		h.logger.Error("admin: list users for sessions", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	userMap := make(map[string]string, len(users))
	for _, u := range users {
		userMap[u.ID] = u.Username
	}

	rows := make([]sessionRow, len(sessions))
	for i, s := range sessions {
		rows[i] = sessionRow{
			Session:  s,
			Username: userMap[s.UserID],
			Device:   session.DeviceSummary(s.UserAgent),
		}
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-sessions", sessionsData{
		basePage: h.baseFlash(r, "sessions", flash),
		Sessions: rows,
	})
}

// PostRevokeSession revokes a session by its public (non-secret) identifier.
// The raw session ID is the bearer token and must never appear in URLs.
func (h *Handler) PostRevokeSession(w http.ResponseWriter, r *http.Request) {
	publicID := chi.URLParam(r, "id")
	if err := h.sessions.RevokeSessionByPublicID(r.Context(), publicID); err != nil {
		h.logger.Error("admin: revoke session", "public_id", publicID, "error", err)
		if r.Header.Get("HX-Request") != "true" {
			http.Redirect(w, r, "/admin/sessions?flash=error", http.StatusFound)
			return
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.logAudit(r, AuditActionSessionRevoke, "session", publicID, "")

	// Support htmx partial response.
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<tr><td colspan="5"><em>Session revoked</em></td></tr>`)
		return
	}

	http.Redirect(w, r, "/admin/sessions?flash=revoked", http.StatusFound)
}

// ─── Settings ────────────────────────────────────────────────────────────────

// settingsPageData is the template data for the settings page. The page is
// organised into tabs, one section each; a tab is a separate form so saving
// "Email" cannot rewrite "Rate limits".
type settingsPageData struct {
	basePage
	Tabs   []settingsTabLink
	Active settingsSection
}

type settingsTabLink struct {
	ID     string
	Title  string
	Active bool
}

// settingsSectionByID returns the requested section, defaulting to the first.
func settingsSectionByID(sections []settingsSection, id string) settingsSection {
	for _, s := range sections {
		if s.ID == id {
			return s
		}
	}
	return sections[0]
}

func (h *Handler) settingsTabsFor(activeID string) []settingsTabLink {
	out := make([]settingsTabLink, 0, len(settingsTabs))
	for _, t := range settingsTabs {
		out = append(out, settingsTabLink{ID: t.ID, Title: t.Title, Active: t.ID == activeID})
	}
	return out
}

// GetSettings renders the requested settings tab.
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}
	sec := settingsSectionByID(h.settingsSections(r.Context(), nil), r.URL.Query().Get("tab"))
	h.render(w, r, "admin-settings", settingsPageData{
		basePage: h.baseFlash(r, "settings", flash),
		Tabs:     h.settingsTabsFor(sec.ID),
		Active:   sec,
	})
}

// PostSettings validates and stores one tab.
func (h *Handler) PostSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/settings", http.StatusFound)
		return
	}
	ctx := r.Context()
	tab := r.FormValue("tab")
	sec := settingsSectionByID(h.settingsSections(ctx, nil), tab)

	values, problems := h.parseSettingsSection(r, sec)
	if len(problems) == 0 {
		problems = h.crossFieldProblems(sec, values)
	}
	if len(problems) > 0 {
		// Re-render with what was typed and every problem listed, so nothing is
		// lost and the operator does not have to guess.
		h.render(w, r, "admin-settings", settingsPageData{
			basePage: h.baseFlash(r, "settings", &Flash{Type: "error", Message: strings.Join(problems, " ")}),
			Tabs:     h.settingsTabsFor(sec.ID),
			Active:   settingsSectionByID(h.settingsSections(ctx, values), sec.ID),
		})
		return
	}

	for key, value := range values {
		if err := h.settings.Set(ctx, key, value); err != nil {
			h.logger.Error("admin: set setting", "key", key, "error", err)
			h.render(w, r, "admin-settings", settingsPageData{
				basePage: h.baseFlash(r, "settings", &Flash{Type: "error", Message: "Failed to save settings. Please try again."}),
				Tabs:     h.settingsTabsFor(sec.ID),
				Active:   settingsSectionByID(h.settingsSections(ctx, values), sec.ID),
			})
			return
		}
	}

	h.logAudit(r, AuditActionSettingsUpdate, "settings", "", sec.ID)
	if h.settingsReload != nil {
		h.settingsReload(ctx)
	}
	http.Redirect(w, r, "/admin/settings?tab="+sec.ID+"&flash=updated", http.StatusFound)
}

// crossFieldProblems enforces rules that span more than one field.
func (h *Handler) crossFieldProblems(sec settingsSection, values map[string]string) []string {
	if sec.ID != "auth" {
		return nil
	}
	if values[settings.PasswordEnabled] != "true" &&
		values[settings.PasskeyEnabled] != "true" &&
		values[settings.MagicLinkEnabled] != "true" {
		return []string{"At least one authentication method must stay enabled."}
	}
	if values[settings.MagicLinkEnabled] == "true" {
		// The stored SMTP host is the truth; the config snapshot may be older.
		host := settings.String(context.Background(), h.settings, settings.SMTPHost, h.cfg.SMTP.Host)
		if host == "" {
			return []string{"Magic link needs an SMTP host; set one under Email first."}
		}
	}
	return nil
}

// ─── Audit log ────────────────────────────────────────────────────────────────

type auditLogData struct {
	basePage
	Events       []*AuditEvent
	ActionFilter string
}

// GetAuditLog renders the admin audit log page.
func (h *Handler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	actionFilter := r.URL.Query().Get("action")
	events, err := h.audit.List(r.Context(), AuditFilter{Action: actionFilter, Limit: 100})
	if err != nil {
		h.logger.Error("admin: list audit log", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.render(w, r, "admin-logs", logsData{
		basePage: h.base(r, "logs"),
		Tab:      logTabAdmin,
		Admin: auditLogData{
			Events:       events,
			ActionFilter: actionFilter,
		},
	})
}

// logAudit records an admin audit event. It extracts the acting user from the
// request context and the client IP from r.RemoteAddr. Errors are non-fatal.
func (h *Handler) logAudit(r *http.Request, action, targetType, targetID, targetName string) {
	actorID := ""
	actorName := ""
	if u, ok := session.UserFromContext(r.Context()); ok {
		actorID = u.ID
		actorName = u.Username
	}

	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}

	h.audit.Log(r.Context(), &AuditEvent{
		ActorID:    actorID,
		ActorName:  actorName,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		TargetName: targetName,
		IPAddress:  ip,
	})
}
