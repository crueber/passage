package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

const (
	// defaultAuditLimit is the page size for /audit when none is requested.
	defaultAuditLimit = 50
	// maxAuditLimit caps a caller-supplied page size so one request cannot ask
	// the database for the whole audit table.
	maxAuditLimit = 500
	// maxAuditPage bounds pagination arithmetic. Without it a huge ?page= would
	// overflow the offset into a negative number and silently return page one.
	maxAuditPage = 100000
)

// userSource is the read side of the user store. Defined at the consumer
// boundary; backed by *user.SQLiteStore in run.go.
type userSource interface {
	List(ctx context.Context) ([]*user.User, error)
	GetByID(ctx context.Context, id string) (*user.User, error)
}

// appSource is the read side of the app store.
type appSource interface {
	List(ctx context.Context) ([]*app.App, error)
	GetByID(ctx context.Context, id string) (*app.App, error)
}

// sessionSource is the read side of the session store.
type sessionSource interface {
	ListAll(ctx context.Context) ([]*session.Session, error)
}

// AuditRecord is one administrative audit entry. It mirrors the admin UI's
// event type rather than importing it, so this package and internal/admin stay
// independent; run.go adapts *admin.AuditService to auditSource.
type AuditRecord struct {
	ID         string
	ActorID    string
	ActorName  string
	Action     string
	TargetType string
	TargetID   string
	TargetName string
	Detail     string
	IPAddress  string
	CreatedAt  time.Time
}

// auditSource reads administrative audit entries.
type auditSource interface {
	ListAudit(ctx context.Context, limit, offset int) ([]AuditRecord, error)
}

// Handler serves the read-only /api/v1 endpoints. It holds no state beyond its
// dependencies; every request is authenticated by RequireToken before it gets
// here, so no handler needs to know about tokens beyond the context value.
type Handler struct {
	users    userSource
	apps     appSource
	sessions sessionSource
	audit    auditSource
	logger   *slog.Logger
}

// NewHandler creates a Handler with all dependencies wired.
func NewHandler(
	users userSource,
	apps appSource,
	sessions sessionSource,
	audit auditSource,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		users:    users,
		apps:     apps,
		sessions: sessions,
		audit:    audit,
		logger:   logger,
	}
}

// Routes registers the API endpoints. The router is mounted at /api/v1 behind
// RequireToken. There are deliberately no mutation routes.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/whoami", h.GetWhoami)
	r.Get("/users", h.GetUsers)
	r.Get("/users/{id}", h.GetUser)
	r.Get("/apps", h.GetApps)
	r.Get("/apps/{id}", h.GetApp)
	r.Get("/sessions", h.GetSessions)
	r.Get("/audit", h.GetAudit)
}

// ─── response shapes ─────────────────────────────────────────────────────────

// whoamiResponse identifies the calling token. Scope is always "read-only":
// the API is administrative but exposes no mutations.
type whoamiResponse struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Scope      string  `json:"scope"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}

// userResponse is the public shape of a user. It deliberately has no
// password_hash field and no credential material of any kind.
type userResponse struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	IsAdmin       bool   `json:"is_admin"`
	IsActive      bool   `json:"is_active"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type usersResponse struct {
	Users []userResponse `json:"users"`
}

// appResponse is the public shape of an app. client_id is a public OAuth
// identifier, not a secret; client_secret_hash and redirect URIs are omitted.
type appResponse struct {
	ID                   string `json:"id"`
	Slug                 string `json:"slug"`
	Name                 string `json:"name"`
	Description          string `json:"description"`
	HostPattern          string `json:"host_pattern"`
	DefaultURL           string `json:"default_url"`
	IsActive             bool   `json:"is_active"`
	SessionDurationHours int    `json:"session_duration_hours"`
	OAuthEnabled         bool   `json:"oauth_enabled"`
	ClientID             string `json:"client_id"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
}

type appsResponse struct {
	Apps []appResponse `json:"apps"`
}

// sessionResponse exposes the session's public identifier only. The session ID
// itself is a bearer token and must never be serialised.
type sessionResponse struct {
	PublicID   string  `json:"public_id"`
	UserID     string  `json:"user_id"`
	Username   string  `json:"username"`
	AppID      *string `json:"app_id"`
	IPAddress  string  `json:"ip_address"`
	UserAgent  string  `json:"user_agent"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	ExpiresAt  string  `json:"expires_at"`
}

type sessionsResponse struct {
	Sessions []sessionResponse `json:"sessions"`
}

type auditEventResponse struct {
	ID         string `json:"id"`
	ActorID    string `json:"actor_id"`
	ActorName  string `json:"actor_name"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	Detail     string `json:"detail"`
	IPAddress  string `json:"ip_address"`
	CreatedAt  string `json:"created_at"`
}

type auditResponse struct {
	Events []auditEventResponse `json:"events"`
	Page   int                  `json:"page"`
	Limit  int                  `json:"limit"`
}

// ─── handlers ────────────────────────────────────────────────────────────────

// GetWhoami reports the token that authenticated the request.
func (h *Handler) GetWhoami(w http.ResponseWriter, r *http.Request) {
	t, ok := TokenFromContext(r.Context())
	if !ok {
		// Unreachable behind RequireToken; failing closed is still correct.
		writeUnauthorized(w)
		return
	}
	writeJSON(w, http.StatusOK, whoamiResponse{
		ID:         t.ID,
		Name:       t.Name,
		Scope:      "read-only",
		CreatedAt:  rfc3339(t.CreatedAt),
		LastUsedAt: rfc3339Ptr(t.LastUsedAt),
	})
}

// GetUsers returns every user account.
func (h *Handler) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.users.List(r.Context())
	if err != nil {
		h.logError("list users", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	out := make([]userResponse, len(users))
	for i, u := range users {
		out[i] = userPayload(u)
	}
	writeJSON(w, http.StatusOK, usersResponse{Users: out})
}

// GetUser returns one user, or 404.
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	u, err := h.users.GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logError("get user", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, userPayload(u))
}

// GetApps returns every registered app.
func (h *Handler) GetApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.apps.List(r.Context())
	if err != nil {
		h.logError("list apps", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	out := make([]appResponse, len(apps))
	for i, a := range apps {
		out[i] = appPayload(a)
	}
	writeJSON(w, http.StatusOK, appsResponse{Apps: out})
}

// GetApp returns one app, or 404.
func (h *Handler) GetApp(w http.ResponseWriter, r *http.Request) {
	a, err := h.apps.GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logError("get app", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, appPayload(a))
}

// GetSessions returns every active session, with usernames resolved for
// readability. A failure to load users degrades the usernames to empty rather
// than failing the whole listing.
func (h *Handler) GetSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := h.sessions.ListAll(r.Context())
	if err != nil {
		h.logError("list sessions", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	usernames := make(map[string]string)
	if users, err := h.users.List(r.Context()); err != nil {
		h.logger.Warn("adminapi: list users for session usernames", "error", err)
	} else {
		for _, u := range users {
			usernames[u.ID] = u.Username
		}
	}

	out := make([]sessionResponse, len(sessions))
	for i, s := range sessions {
		var appID *string
		if s.AppID != nil {
			appID = s.AppID
		}
		out[i] = sessionResponse{
			PublicID:   s.PublicID,
			UserID:     s.UserID,
			Username:   usernames[s.UserID],
			AppID:      appID,
			IPAddress:  s.IPAddress,
			UserAgent:  s.UserAgent,
			CreatedAt:  rfc3339(s.CreatedAt),
			LastUsedAt: rfc3339Ptr(s.LastUsedAt),
			ExpiresAt:  rfc3339(s.ExpiresAt),
		}
	}
	writeJSON(w, http.StatusOK, sessionsResponse{Sessions: out})
}

// GetAudit returns one page of administrative audit events, newest first.
func (h *Handler) GetAudit(w http.ResponseWriter, r *http.Request) {
	page, limit := auditPage(r)
	events, err := h.audit.ListAudit(r.Context(), limit, (page-1)*limit)
	if err != nil {
		h.logError("list audit events", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	out := make([]auditEventResponse, len(events))
	for i, e := range events {
		out[i] = auditEventResponse{
			ID:         e.ID,
			ActorID:    e.ActorID,
			ActorName:  e.ActorName,
			Action:     e.Action,
			TargetType: e.TargetType,
			TargetID:   e.TargetID,
			TargetName: e.TargetName,
			Detail:     e.Detail,
			IPAddress:  e.IPAddress,
			CreatedAt:  rfc3339(e.CreatedAt),
		}
	}
	writeJSON(w, http.StatusOK, auditResponse{Events: out, Page: page, Limit: limit})
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// userPayload converts a stored user into its public shape.
func userPayload(u *user.User) userResponse {
	return userResponse{
		ID:            u.ID,
		Username:      u.Username,
		Email:         u.Email,
		Name:          u.Name,
		IsAdmin:       u.IsAdmin,
		IsActive:      u.IsActive,
		EmailVerified: u.EmailVerified,
		CreatedAt:     rfc3339(u.CreatedAt),
		UpdatedAt:     rfc3339(u.UpdatedAt),
	}
}

// appPayload converts a stored app into its public shape.
func appPayload(a *app.App) appResponse {
	return appResponse{
		ID:                   a.ID,
		Slug:                 a.Slug,
		Name:                 a.Name,
		Description:          a.Description,
		HostPattern:          a.HostPattern,
		DefaultURL:           a.DefaultURL,
		IsActive:             a.IsActive,
		SessionDurationHours: a.SessionDurationHours,
		OAuthEnabled:         a.OAuthEnabled,
		ClientID:             a.ClientID,
		CreatedAt:            rfc3339(a.CreatedAt),
		UpdatedAt:            rfc3339(a.UpdatedAt),
	}
}

// auditPage reads ?page= and ?limit= defensively: invalid values fall back to
// the defaults instead of erroring, and limit is capped.
func auditPage(r *http.Request) (page, limit int) {
	limit = defaultAuditLimit
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}

	page = 1
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n > 1 {
		page = n
	}
	if page > maxAuditPage {
		page = maxAuditPage
	}
	return page, limit
}

// rfc3339 formats a timestamp for the API. Every time in a response is UTC
// RFC 3339 so clients never have to guess a layout or a zone.
func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// rfc3339Ptr is rfc3339 with a null for the zero time, used for optional
// timestamps such as "never used".
func rfc3339Ptr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := rfc3339(t)
	return &s
}

// logError records an internal failure without leaking it to the client.
func (h *Handler) logError(op string, err error) {
	h.logger.Error("adminapi: "+op, "error", err)
}

// writeJSON writes a JSON response. The encode error is ignored on purpose:
// the status and headers are already committed, so there is nothing left to
// recover, and the body is always a small in-memory value.
//
// Cache-Control: no-store keeps user, session, and audit data out of any
// intermediary or browser cache; the API answers administrative questions.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error envelope with a stable field name.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}
