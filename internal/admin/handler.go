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
	"path"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/email"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
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
}

// sessionServiceOps is the minimal interface for session management.
// Defined at the consumer boundary.
type sessionServiceOps interface {
	ListAll(ctx context.Context) ([]*session.Session, error)
	RevokeSession(ctx context.Context, token string) error
	RevokeAllByUser(ctx context.Context, userID string) error
}

// credentialCounter is the minimal interface for querying passkey credential counts.
// Defined at the consumer boundary.
type credentialCounter interface {
	CountByUser(ctx context.Context, userID string) (int, error)
}

// auditLogger is the minimal interface for recording admin audit events.
// Defined at the consumer boundary.
type auditLogger interface {
	Log(ctx context.Context, e *AuditEvent)
	List(ctx context.Context, f AuditFilter) ([]*AuditEvent, error)
}

// Handler holds all admin HTTP handlers in one struct.
type Handler struct {
	userStore   userStore
	userSvc     userServiceOps
	sessions    sessionServiceOps
	apps        appServiceOps
	settings    SettingsStore
	credentials credentialCounter
	audit       auditLogger
	mailer      email.Sender
	tmpl        *template.Template
	cfg         *config.Config
	logger      *slog.Logger
}

// NewHandler creates a new admin Handler with all dependencies wired.
func NewHandler(
	userStore userStore,
	userSvc userServiceOps,
	sessions sessionServiceOps,
	apps appServiceOps,
	settings SettingsStore,
	credentials credentialCounter,
	mailer email.Sender,
	tmpl *template.Template,
	cfg *config.Config,
	logger *slog.Logger,
	audit auditLogger,
) *Handler {
	return &Handler{
		userStore:   userStore,
		userSvc:     userSvc,
		sessions:    sessions,
		apps:        apps,
		settings:    settings,
		credentials: credentials,
		audit:       audit,
		mailer:      mailer,
		tmpl:        tmpl,
		cfg:         cfg,
		logger:      logger,
	}
}

// Routes registers all admin routes on the given chi.Router.
// The router should already be mounted at /admin and protected by RequireAdmin.
func (h *Handler) Routes(r chi.Router) {
	// Dashboard
	r.Get("/", h.GetDashboard)

	// Users
	r.Get("/users", h.GetUsers)
	r.Get("/users/new", h.GetNewUser)
	r.Post("/users", h.PostCreateUser)
	r.Get("/users/{id}", h.GetEditUser)
	r.Post("/users/{id}", h.PostUpdateUser)
	r.Post("/users/{id}/delete", h.PostDeleteUser)
	r.Post("/users/{id}/reset-password", h.PostResetUserPassword)
	r.Post("/users/{id}/sessions/revoke-all", h.PostRevokeAllUserSessions)
	r.Get("/users/{id}/apps", h.GetUserApps)
	r.Post("/users/{id}/apps", h.PostUserApps)

	// Apps
	r.Get("/apps", h.GetApps)
	r.Get("/apps/new", h.GetNewApp)
	r.Post("/apps", h.PostCreateApp)
	r.Get("/apps/{id}", h.GetEditApp)
	r.Post("/apps/{id}", h.PostUpdateApp)
	r.Post("/apps/{id}/delete", h.PostDeleteApp)
	r.Get("/apps/{id}/access", h.GetAppAccess)
	r.Post("/apps/{id}/access", h.PostGrantAccess)
	r.Post("/apps/{id}/access/{userId}/revoke", h.PostRevokeAccess)
	r.Post("/apps/{id}/oauth/generate", h.PostGenerateOAuthCredentials)
	r.Post("/apps/{id}/oauth/rotate", h.PostRotateOAuthSecret)

	// Sessions
	r.Get("/sessions", h.GetSessions)
	r.Post("/sessions/{id}/revoke", h.PostRevokeSession)

	// Settings
	r.Get("/settings", h.GetSettings)
	r.Post("/settings", h.PostSettings)

	// Audit log
	r.Get("/audit-log", h.GetAuditLog)
}

// ─── base page data ──────────────────────────────────────────────────────────

// basePage is embedded into every admin page data struct.
type basePage struct {
	ActiveNav string
	Flash     *Flash
	CSRFToken string
}

// base constructs a basePage for the given request, populating the CSRF token
// from the request context (set by csrf.ProtectAuthenticated middleware).
func (h *Handler) base(r *http.Request, nav string) basePage {
	return basePage{
		ActiveNav: nav,
		CSRFToken: csrf.TokenFromContext(r.Context()),
	}
}

// baseFlash constructs a basePage with an attached Flash message.
func (h *Handler) baseFlash(r *http.Request, nav string, flash *Flash) basePage {
	return basePage{
		ActiveNav: nav,
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

	h.render(w, r, "admin-dashboard", dashboardData{
		basePage:     h.base(r, "dashboard"),
		UserCount:    len(users),
		AppCount:     len(apps),
		SessionCount: len(sessions),
	})
}

// ─── Users ───────────────────────────────────────────────────────────────────

type usersData struct {
	basePage
	Users []*user.User
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

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-users", usersData{
		basePage: h.baseFlash(r, "users", flash),
		Users:    users,
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

	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cfg.Auth.BcryptCost)
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
		appsWithAccess[i] = appWithAccess{
			App:       a,
			HasAccess: accessMap[a.ID],
		}
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

// PostUserApps handles bulk grant/revoke of app access for a user.
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
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/users/%s/apps?flash=updated", id), http.StatusFound)
}

// ─── Apps ────────────────────────────────────────────────────────────────────

type appsData struct {
	basePage
	Apps []*app.App
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

	h.render(w, r, "admin-apps", appsData{
		basePage: h.baseFlash(r, "apps", flash),
		Apps:     apps,
	})
}

type appFormData struct {
	basePage
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
		BaseURL:  h.baseURL(),
	})
}

// PostCreateApp handles app creation.
func (h *Handler) PostCreateApp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Invalid form submission."}),
			IsNew:    true,
			BaseURL:  h.baseURL(),
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

	// Parse optional per-app session duration override.
	var appSessionDuration int
	if raw := strings.TrimSpace(r.FormValue("session_duration_hours")); raw != "" && raw != "0" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			h.render(w, r, "admin-app-form", appFormData{
				basePage: h.baseFlash(r, "apps", &Flash{Type: "error",
					Message: "Session duration must be a non-negative integer (0 = use global default)."}),
				EditApp: a,
				IsNew:   true,
				BaseURL: h.baseURL(),
			})
			return
		}
		appSessionDuration = n
	}
	a.SessionDurationHours = appSessionDuration

	if a.Slug == "" || a.Name == "" {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Slug and name are required."}),
			EditApp:  a,
			IsNew:    true,
			BaseURL:  h.baseURL(),
		})
		return
	}

	if a.DefaultURL != "" && !strings.HasPrefix(a.DefaultURL, "http://") && !strings.HasPrefix(a.DefaultURL, "https://") {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Default URL must start with http:// or https://."}),
			EditApp:  a,
			IsNew:    true,
			BaseURL:  h.baseURL(),
		})
		return
	}

	if _, err := path.Match(a.HostPattern, "test.example.com"); err != nil {
		// path.Match only returns an error for syntactically malformed patterns.
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Host pattern is malformed: " + err.Error()}),
			EditApp:  a,
			IsNew:    true,
			BaseURL:  h.baseURL(),
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
			BaseURL:  h.baseURL(),
		})
		return
	}

	h.logAudit(r, AuditActionAppCreate, "app", a.ID, a.Name)
	http.Redirect(w, r, "/admin/apps?flash=created", http.StatusFound)
}

// GetEditApp renders the edit app form.
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

	h.render(w, r, "admin-app-form", appFormData{
		basePage: h.base(r, "apps"),
		EditApp:  a,
		IsNew:    false,
		BaseURL:  h.baseURL(),
	})
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

	// Parse optional per-app session duration override.
	var appSessionDuration int
	if raw := strings.TrimSpace(r.FormValue("session_duration_hours")); raw != "" && raw != "0" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			h.render(w, r, "admin-app-form", appFormData{
				basePage: h.baseFlash(r, "apps", &Flash{Type: "error",
					Message: "Session duration must be a non-negative integer (0 = use global default)."}),
				EditApp: a,
				IsNew:   false,
				BaseURL: h.baseURL(),
			})
			return
		}
		appSessionDuration = n
	}
	a.SessionDurationHours = appSessionDuration

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
			EditApp:  a,
			IsNew:    false,
			BaseURL:  h.baseURL(),
		})
		return
	}

	if a.DefaultURL != "" && !strings.HasPrefix(a.DefaultURL, "http://") && !strings.HasPrefix(a.DefaultURL, "https://") {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Default URL must start with http:// or https://."}),
			EditApp:  a,
			IsNew:    false,
			BaseURL:  h.baseURL(),
		})
		return
	}

	if _, err := path.Match(a.HostPattern, "test.example.com"); err != nil {
		// path.Match only returns an error for syntactically malformed patterns.
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Host pattern is malformed: " + err.Error()}),
			EditApp:  a,
			IsNew:    false,
			BaseURL:  h.baseURL(),
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
			EditApp:  a,
			IsNew:    false,
			BaseURL:  h.baseURL(),
		})
		return
	}

	h.logAudit(r, AuditActionAppUpdate, "app", a.ID, a.Name)
	http.Redirect(w, r, "/admin/apps?flash=updated", http.StatusFound)
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
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
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
	h.render(w, r, "admin-app-form", appFormData{
		basePage:        h.baseFlash(r, "apps", &Flash{Type: "success", Message: "OAuth credentials generated. Copy the secret — it will not be shown again."}),
		EditApp:         a,
		NewClientSecret: secret,
		BaseURL:         h.cfg.Server.BaseURL,
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
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
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
	h.render(w, r, "admin-app-form", appFormData{
		basePage:        h.baseFlash(r, "apps", &Flash{Type: "success", Message: "OAuth client secret rotated. Copy the new secret — it will not be shown again."}),
		EditApp:         a,
		NewClientSecret: secret,
		BaseURL:         h.cfg.Server.BaseURL,
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
	App                *app.App
	UsersWithAccess    []userWithAccess
	UsersWithoutAccess []*user.User
}

// appWithAccess bundles an app with whether the given user has access.
type appWithAccess struct {
	App       *app.App
	HasAccess bool
}

// userAppsData is the template data for the user app access page.
type userAppsData struct {
	basePage
	EditUser       *user.User
	AppsWithAccess []appWithAccess
}

// GetAppAccess renders the app access management page.
func (h *Handler) GetAppAccess(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	a, err := h.apps.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return
		}
		h.logger.Error("admin: get app for access", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	accesses, err := h.apps.ListUsersWithAccess(ctx, id)
	if err != nil {
		h.logger.Error("admin: list users with access", "app_id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	allUsers, err := h.userStore.List(ctx)
	if err != nil {
		h.logger.Error("admin: list users for access page", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
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

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-app-access", appAccessData{
		basePage:           h.baseFlash(r, "apps", flash),
		App:                a,
		UsersWithAccess:    withAccess,
		UsersWithoutAccess: withoutAccess,
	})
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
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/access", appID), http.StatusFound)
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
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/access?flash=access-granted", appID), http.StatusFound)
}

// PostRevokeAccess revokes a user's access to an app.
func (h *Handler) PostRevokeAccess(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "userId")

	if err := h.apps.RevokeAccess(r.Context(), userID, appID); err != nil {
		h.logger.Error("admin: revoke access", "user_id", userID, "app_id", appID, "error", err)
		if r.Header.Get("HX-Request") != "true" {
			http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/access?flash=error", appID), http.StatusFound)
			return
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Best-effort fetch for audit target_name.
	appName := appID
	if a, err := h.apps.GetByID(r.Context(), appID); err == nil {
		appName = a.Name
	}
	h.logAudit(r, AuditActionAppRevokeAccess, "app", appID, appName)

	// Support htmx partial response (return empty row with "Revoked" indicator).
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<tr><td colspan="3"><em>Access revoked</em></td></tr>`)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/access?flash=access-revoked", appID), http.StatusFound)
}

// ─── Sessions ────────────────────────────────────────────────────────────────

// sessionRow bundles a session with its user's username for display.
type sessionRow struct {
	Session  *session.Session
	Username string
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

// PostRevokeSession revokes a session by its token ID.
func (h *Handler) PostRevokeSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.sessions.RevokeSession(r.Context(), id); err != nil {
		h.logger.Error("admin: revoke session", "id", id, "error", err)
		if r.Header.Get("HX-Request") != "true" {
			http.Redirect(w, r, "/admin/sessions?flash=error", http.StatusFound)
			return
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.logAudit(r, AuditActionSessionRevoke, "session", id, "")

	// Support htmx partial response.
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<tr><td colspan="5"><em>Session revoked</em></td></tr>`)
		return
	}

	http.Redirect(w, r, "/admin/sessions?flash=revoked", http.StatusFound)
}

// ─── Settings ────────────────────────────────────────────────────────────────

type settingsData struct {
	basePage
	AllowRegistration    string
	SessionDurationHours string
	SMTPFrom             string
}

// GetSettings renders the settings page.
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	all, err := h.settings.GetAll(ctx)
	if err != nil {
		h.logger.Error("admin: get all settings", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}

	h.render(w, r, "admin-settings", settingsData{
		basePage:             h.baseFlash(r, "settings", flash),
		AllowRegistration:    all["allow_registration"],
		SessionDurationHours: all["session_duration_hours"],
		SMTPFrom:             all["smtp_from"],
	})
}

// PostSettings saves the settings form.
func (h *Handler) PostSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/settings", http.StatusFound)
		return
	}

	ctx := r.Context()

	// allow_registration: checkbox — present means "true", absent means "false"
	allowRegistration := "false"
	if r.FormValue("allow_registration") == "on" {
		allowRegistration = "true"
	}

	// Validate session_duration_hours before writing anything.
	durationStr := strings.TrimSpace(r.FormValue("session_duration_hours"))
	if durationStr != "" {
		n, err := strconv.Atoi(durationStr)
		if err != nil || n <= 0 {
			h.render(w, r, "admin-settings", settingsData{
				basePage:             h.baseFlash(r, "settings", &Flash{Type: "error", Message: "Session duration must be a positive number."}),
				AllowRegistration:    allowRegistration,
				SessionDurationHours: durationStr,
				SMTPFrom:             strings.TrimSpace(r.FormValue("smtp_from")),
			})
			return
		}
	}

	// All validation passed — write settings.
	if err := h.settings.Set(ctx, "allow_registration", allowRegistration); err != nil {
		h.logger.Error("admin: set allow_registration", "error", err)
	}

	if durationStr != "" {
		if err := h.settings.Set(ctx, "session_duration_hours", durationStr); err != nil {
			h.logger.Error("admin: set session_duration_hours", "error", err)
		}
	}

	smtpFrom := strings.TrimSpace(r.FormValue("smtp_from"))
	if err := h.settings.Set(ctx, "smtp_from", smtpFrom); err != nil {
		h.logger.Error("admin: set smtp_from", "error", err)
	}

	h.logAudit(r, AuditActionSettingsUpdate, "settings", "", "")
	http.Redirect(w, r, "/admin/settings?flash=updated", http.StatusFound)
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

	h.render(w, r, "admin-audit-log", auditLogData{
		basePage:     h.base(r, "audit-log"),
		Events:       events,
		ActionFilter: actionFilter,
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
