package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
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
	GrantAccess(ctx context.Context, userID, appID string) error
	RevokeAccess(ctx context.Context, userID, appID string) error
}

// sessionServiceOps is the minimal interface for session management.
// Defined at the consumer boundary.
type sessionServiceOps interface {
	ListAll(ctx context.Context) ([]*session.Session, error)
	RevokeSession(ctx context.Context, token string) error
}

// credentialCounter is the minimal interface for querying passkey credential counts.
// Defined at the consumer boundary.
type credentialCounter interface {
	CountByUser(ctx context.Context, userID string) (int, error)
}

// Handler holds all admin HTTP handlers in one struct.
type Handler struct {
	userStore   userStore
	userSvc     userServiceOps
	sessions    sessionServiceOps
	apps        appServiceOps
	settings    SettingsStore
	credentials credentialCounter
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
) *Handler {
	return &Handler{
		userStore:   userStore,
		userSvc:     userSvc,
		sessions:    sessions,
		apps:        apps,
		settings:    settings,
		credentials: credentials,
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

	// Sessions
	r.Get("/sessions", h.GetSessions)
	r.Post("/sessions/{id}/revoke", h.PostRevokeSession)

	// Settings
	r.Get("/settings", h.GetSettings)
	r.Post("/settings", h.PostSettings)
}

// ─── base page data ──────────────────────────────────────────────────────────

// basePage is embedded into every admin page data struct.
type basePage struct {
	ActiveNav string
	Flash     *Flash
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
		basePage:     basePage{ActiveNav: "dashboard"},
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
		basePage: basePage{ActiveNav: "users", Flash: flash},
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
		basePage: basePage{ActiveNav: "users"},
		IsNew:    true,
	})
}

// PostCreateUser handles admin user creation, bypassing allow_registration.
func (h *Handler) PostCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "admin-user-form", userFormData{
			basePage: basePage{ActiveNav: "users", Flash: &Flash{Type: "error", Message: "Invalid form submission."}},
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
			basePage: basePage{ActiveNav: "users", Flash: &Flash{Type: "error", Message: msg}},
			IsNew:    true,
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cfg.Auth.BcryptCost)
	if err != nil {
		h.logger.Error("admin: hash password", "error", err)
		h.render(w, r, "admin-user-form", userFormData{
			basePage: basePage{ActiveNav: "users", Flash: &Flash{Type: "error", Message: "Internal error. Please try again."}},
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
			basePage: basePage{ActiveNav: "users", Flash: &Flash{Type: "error", Message: msg}},
			IsNew:    true,
		})
		return
	}

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
		basePage:     basePage{ActiveNav: "users"},
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
			basePage: basePage{ActiveNav: "users", Flash: &Flash{Type: "error", Message: "Username and email are required."}},
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
			basePage: basePage{ActiveNav: "users", Flash: &Flash{Type: "error", Message: msg}},
			EditUser: u,
			IsNew:    false,
		})
		return
	}

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

	if err := h.userStore.Delete(r.Context(), id); err != nil && !errors.Is(err, user.ErrNotFound) {
		h.logger.Error("admin: delete user", "id", id, "error", err)
		http.Redirect(w, r, "/admin/users", http.StatusFound)
		return
	}
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

	http.Redirect(w, r, "/admin/users?flash=reset-sent", http.StatusFound)
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
		basePage: basePage{ActiveNav: "apps", Flash: flash},
		Apps:     apps,
	})
}

type appFormData struct {
	basePage
	EditApp *app.App
	IsNew   bool
}

// GetNewApp renders the new app form.
func (h *Handler) GetNewApp(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin-app-form", appFormData{
		basePage: basePage{ActiveNav: "apps"},
		IsNew:    true,
	})
}

// PostCreateApp handles app creation.
func (h *Handler) PostCreateApp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: basePage{ActiveNav: "apps", Flash: &Flash{Type: "error", Message: "Invalid form submission."}},
			IsNew:    true,
		})
		return
	}

	a := &app.App{
		Slug:        strings.TrimSpace(r.FormValue("slug")),
		Name:        strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")),
		HostPattern: strings.TrimSpace(r.FormValue("host_pattern")),
		IsActive:    r.FormValue("is_active") == "on",
	}

	if a.Slug == "" || a.Name == "" {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: basePage{ActiveNav: "apps", Flash: &Flash{Type: "error", Message: "Slug and name are required."}},
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
			basePage: basePage{ActiveNav: "apps", Flash: &Flash{Type: "error", Message: msg}},
			EditApp:  a,
			IsNew:    true,
		})
		return
	}

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
		basePage: basePage{ActiveNav: "apps"},
		EditApp:  a,
		IsNew:    false,
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
	a.IsActive = r.FormValue("is_active") == "on"

	if a.Slug == "" || a.Name == "" {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: basePage{ActiveNav: "apps", Flash: &Flash{Type: "error", Message: "Slug and name are required."}},
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
			basePage: basePage{ActiveNav: "apps", Flash: &Flash{Type: "error", Message: msg}},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	http.Redirect(w, r, "/admin/apps?flash=updated", http.StatusFound)
}

// PostDeleteApp deletes an app by ID.
func (h *Handler) PostDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.apps.Delete(r.Context(), id); err != nil && !errors.Is(err, app.ErrNotFound) {
		h.logger.Error("admin: delete app", "id", id, "error", err)
		http.Redirect(w, r, "/admin/apps?flash=error", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/apps?flash=deleted", http.StatusFound)
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
		basePage:           basePage{ActiveNav: "apps", Flash: flash},
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
		basePage: basePage{ActiveNav: "sessions", Flash: flash},
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
		basePage:             basePage{ActiveNav: "settings", Flash: flash},
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
				basePage:             basePage{ActiveNav: "settings", Flash: &Flash{Type: "error", Message: "Session duration must be a positive number."}},
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

	http.Redirect(w, r, "/admin/settings?flash=updated", http.StatusFound)
}
