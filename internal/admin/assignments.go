package admin

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/user"
)

// assignmentOption is one checkbox row on the user assignments page.
type assignmentOption struct {
	ID          string
	Name        string
	Description string
	Assigned    bool
}

// appAssignmentsData backs the per-user group/role assignment page.
type appAssignmentsData struct {
	basePage
	appTabs
	User      *user.User
	Groups    []assignmentOption
	Roles     []assignmentOption
	Inherited []namedItemRow // role-inherited groups; read-only
}

// loadAppUser resolves both the {id} app and {userId} user URL params,
// writing the error response itself. The bool is false when the response is
// already written.
func (h *Handler) loadAppUser(w http.ResponseWriter, r *http.Request, purpose string) (*app.App, *user.User, bool) {
	a, ok := h.getAppForAdmin(w, r, purpose)
	if !ok {
		return nil, nil, false
	}
	u, err := h.userStore.GetByID(r.Context(), chi.URLParam(r, "userId"))
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps/"+a.ID+"/access?flash=error", http.StatusFound)
			return nil, nil, false
		}
		h.logger.Error("admin: get user for "+purpose, "user_id", chi.URLParam(r, "userId"), "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, nil, false
	}
	return a, u, true
}

// assignmentsURL is the canonical URL of a user's assignment page.
func assignmentsURL(appID, userID string) string {
	return fmt.Sprintf("/admin/apps/%s/access/%s/assignments", appID, userID)
}

// GetAppUserAssignments renders the assignment page for one user and app.
func (h *Handler) GetAppUserAssignments(w http.ResponseWriter, r *http.Request) {
	a, u, ok := h.loadAppUser(w, r, "user assignments")
	if !ok {
		return
	}

	data, err := h.buildAssignmentsData(r, a, u,
		h.baseFlash(r, "apps", flashFromQuery(r.URL.Query().Get("flash"))))
	if err != nil {
		h.logger.Error("admin: build assignments page", "app_id", a.ID, "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.render(w, r, "admin-app-assignments", data)
}

// buildAssignmentsData assembles the checkbox options and the read-only
// inherited groups list.
func (h *Handler) buildAssignmentsData(r *http.Request, a *app.App, u *user.User, base basePage) (*appAssignmentsData, error) {
	ctx := r.Context()

	allGroups, err := h.apps.ListGroupsByApp(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	directGroups, err := h.apps.ListUserDirectGroups(ctx, u.ID, a.ID)
	if err != nil {
		return nil, err
	}
	inheritedGroups, err := h.apps.ListUserInheritedGroups(ctx, u.ID, a.ID)
	if err != nil {
		return nil, err
	}
	allRoles, err := h.apps.ListRolesByApp(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	userRoles, err := h.apps.ListUserRoles(ctx, u.ID, a.ID)
	if err != nil {
		return nil, err
	}

	directSet := make(map[string]bool, len(directGroups))
	for _, g := range directGroups {
		directSet[g.ID] = true
	}
	roleSet := make(map[string]bool, len(userRoles))
	for _, ro := range userRoles {
		roleSet[ro.ID] = true
	}

	groups := make([]assignmentOption, len(allGroups))
	for i, g := range allGroups {
		groups[i] = assignmentOption{ID: g.ID, Name: g.Name, Description: g.Description, Assigned: directSet[g.ID]}
	}
	roles := make([]assignmentOption, len(allRoles))
	for i, ro := range allRoles {
		roles[i] = assignmentOption{ID: ro.ID, Name: ro.Name, Description: ro.Description, Assigned: roleSet[ro.ID]}
	}

	inherited := make([]namedItemRow, len(inheritedGroups))
	for i, g := range inheritedGroups {
		inherited[i] = namedItemRow{ID: g.ID, Name: g.Name, Description: g.Description}
	}

	return &appAssignmentsData{
		basePage:  base,
		appTabs:   appTabs{App: a, ActiveTab: "access"},
		User:      u,
		Groups:    groups,
		Roles:     roles,
		Inherited: inherited,
	}, nil
}

// PostAppUserAssignments syncs a user's direct groups and roles to the
// submitted checkbox values. Role-inherited groups cannot be modified here —
// they are resolved from role membership at read time.
func (h *Handler) PostAppUserAssignments(w http.ResponseWriter, r *http.Request) {
	a, u, ok := h.loadAppUser(w, r, "save user assignments")
	if !ok {
		return
	}
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, assignmentsURL(a.ID, u.ID)+"?flash=error", http.StatusFound)
		return
	}
	desiredGroups := toIDSet(r.Form["group_ids"])
	desiredRoles := toIDSet(r.Form["role_ids"])

	// Diff direct groups.
	currentGroups, err := h.apps.ListUserDirectGroups(ctx, u.ID, a.ID)
	if err != nil {
		h.logger.Error("admin: list user groups for save", "user_id", u.ID, "app_id", a.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	for _, g := range currentGroups {
		if !desiredGroups[g.ID] {
			if err := h.apps.UnassignUserGroup(ctx, u.ID, a.ID, g.ID); err != nil {
				h.assignmentSaveFailed(w, r, a, u, err)
				return
			}
		}
	}
	for gid := range desiredGroups {
		if err := h.apps.AssignUserGroup(ctx, u.ID, a.ID, gid); err != nil {
			h.assignmentSaveFailed(w, r, a, u, err)
			return
		}
	}

	// Diff roles.
	currentRoles, err := h.apps.ListUserRoles(ctx, u.ID, a.ID)
	if err != nil {
		h.logger.Error("admin: list user roles for save", "user_id", u.ID, "app_id", a.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	for _, ro := range currentRoles {
		if !desiredRoles[ro.ID] {
			if err := h.apps.UnassignUserRole(ctx, u.ID, a.ID, ro.ID); err != nil {
				h.assignmentSaveFailed(w, r, a, u, err)
				return
			}
		}
	}
	for rid := range desiredRoles {
		if err := h.apps.AssignUserRole(ctx, u.ID, a.ID, rid); err != nil {
			h.assignmentSaveFailed(w, r, a, u, err)
			return
		}
	}

	h.logAudit(r, AuditActionAppAssignmentsUpdate, "user", u.ID, u.Username)
	http.Redirect(w, r, assignmentsURL(a.ID, u.ID)+"?flash=updated", http.StatusFound)
}

// assignmentSaveFailed redirects back to the form with an error flash on
// partial-save failures, preserving whatever completed.
func (h *Handler) assignmentSaveFailed(w http.ResponseWriter, r *http.Request, a *app.App, u *user.User, err error) {
	h.logger.Error("admin: save user assignments", "user_id", u.ID, "app_id", a.ID, "error", err)
	http.Redirect(w, r, assignmentsURL(a.ID, u.ID)+"?flash=error", http.StatusFound)
}

// toIDSet converts repeated form values into a set of non-empty IDs.
func toIDSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		if v != "" {
			set[v] = true
		}
	}
	return set
}
