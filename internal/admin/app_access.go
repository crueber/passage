package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/user"
)

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

// loadAppAccessData loads the app plus its with/without-access user lists and
// builds the appAccessData for the access page. Shared by the page render and
// the htmx out-of-band refresh after revoke.
func (h *Handler) loadAppAccessData(w http.ResponseWriter, r *http.Request, appID string, flash *Flash, q url.Values) (*appAccessData, error) {
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

	accessMap := make(map[string]*app.UserAccess, len(accesses))
	for _, ac := range accesses {
		accessMap[ac.UserID] = ac
	}

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
	withPager := h.paginationFor(w, r, q, basePath, "with_page", "per_page", len(withAccess), pageSizeAppAccess)
	withoutPager := h.paginationFor(nil, r, q, basePath, "without_page", "per_page", len(withoutAccess), pageSizeAppAccess)

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

	data, err := h.loadAppAccessData(w, r, id, flash, r.URL.Query())
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
		errQ := cloneQuery(q)
		errQ.Set("flash", "error")
		errURL := appAccessURL(appID, errQ)
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", errURL)
			return
		}
		http.Redirect(w, r, errURL, http.StatusFound)
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
	data, err := h.loadAppAccessData(w, r, appID, nil, q)
	if err != nil {
		h.logger.Error("admin: revoke access oob reload", "app_id", appID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.render(w, r, "admin-app-access-revoke-oob", data)
}
