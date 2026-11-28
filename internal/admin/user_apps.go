package admin

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/user"
)

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

	allGroups, err := h.apps.ListAllGroups(ctx)
	if err != nil {
		h.logger.Error("admin: list all groups for user apps page", "user_id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	allRoles, err := h.apps.ListAllRoles(ctx)
	if err != nil {
		h.logger.Error("admin: list all roles for user apps page", "user_id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	assignments, err := h.apps.ListUserAssignments(ctx, id)
	if err != nil {
		h.logger.Error("admin: list user assignments for user apps page", "user_id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	groupsByApp := make(map[string][]*app.Group)
	for _, g := range allGroups {
		groupsByApp[g.AppID] = append(groupsByApp[g.AppID], g)
	}
	rolesByApp := make(map[string][]*app.Role)
	for _, ro := range allRoles {
		rolesByApp[ro.AppID] = append(rolesByApp[ro.AppID], ro)
	}

	appsWithAccess := make([]appWithAccess, len(allApps))
	for i, a := range allApps {
		appGroups := groupsByApp[a.ID]
		directSet := assignments.DirectGroups[a.ID]
		inheritedSet := assignments.InheritedGroups[a.ID]
		groups := make([]assignmentOption, len(appGroups))
		for j, g := range appGroups {
			groups[j] = assignmentOption{
				ID:          g.ID,
				Name:        g.Name,
				Description: g.Description,
				Assigned:    directSet[g.ID],
				Inherited:   inheritedSet[g.ID],
			}
		}

		appRoles := rolesByApp[a.ID]
		roleSet := assignments.Roles[a.ID]
		roles := make([]assignmentOption, len(appRoles))
		for j, ro := range appRoles {
			roles[j] = assignmentOption{
				ID:          ro.ID,
				Name:        ro.Name,
				Description: ro.Description,
				Assigned:    roleSet[ro.ID],
			}
		}
		appsWithAccess[i] = appWithAccess{App: a, HasAccess: accessMap[a.ID], Groups: groups, Roles: roles}
	}

	h.render(w, r, "admin-user-apps", userAppsData{
		basePage:       h.baseQueryFlash(r, "users"),
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
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s/apps?flash=error", id), http.StatusFound)
		return
	}

	targetUser, err := h.userStore.GetByID(ctx, id)
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

	var hadErr bool
	var assignmentsChanged bool

	for _, a := range allApps {
		inDesired := desiredSet[a.ID]
		inCurrent := currentSet[a.ID]

		if inDesired && !inCurrent {
			if err := h.apps.GrantAccess(ctx, id, a.ID); err != nil {
				h.logger.Error("admin: grant access (bulk)", "user_id", id, "app_id", a.ID, "error", err)
				hadErr = true
			} else {
				h.logAudit(r, AuditActionAppGrantAccess, "app", a.ID, a.Name)
			}
		} else if !inDesired && inCurrent {
			if err := h.apps.RevokeAccess(ctx, id, a.ID); err != nil {
				h.logger.Error("admin: revoke access (bulk)", "user_id", id, "app_id", a.ID, "error", err)
				hadErr = true
			} else {
				h.logAudit(r, AuditActionAppRevokeAccess, "app", a.ID, a.Name)
			}
		}

		// Role and group diffs apply to every app row: the submitted
		// checkboxes reflect what the admin sees, so a save clears
		// assignments even when access is being revoked.
		desiredRoles := toIDSet(r.Form["roles."+a.ID])

		currentRoles, err := h.apps.ListUserRoles(ctx, id, a.ID)
		if err != nil {
			h.logger.Error("admin: list user roles (bulk)", "user_id", id, "app_id", a.ID, "error", err)
			hadErr = true
			continue
		}
		currentRoleSet := make(map[string]bool, len(currentRoles))
		for _, ro := range currentRoles {
			currentRoleSet[ro.ID] = true
			if !desiredRoles[ro.ID] {
				if err := h.apps.UnassignUserRole(ctx, id, a.ID, ro.ID); err != nil {
					h.logger.Error("admin: unassign user role (bulk)", "user_id", id, "app_id", a.ID, "role_id", ro.ID, "error", err)
					hadErr = true
				} else {
					assignmentsChanged = true
				}
			}
		}
		for rid := range desiredRoles {
			if !currentRoleSet[rid] {
				if err := h.apps.AssignUserRole(ctx, id, a.ID, rid); err != nil {
					h.logger.Error("admin: assign user role (bulk)", "user_id", id, "app_id", a.ID, "role_id", rid, "error", err)
					hadErr = true
				} else {
					assignmentsChanged = true
				}
			}
		}

		// Diff direct groups. Role-inherited groups are excluded from the
		// unassign side: their checkboxes render disabled and are not
		// submitted, so the guard protects their direct assignment.
		inheritedGroups, err := h.apps.ListUserInheritedGroups(ctx, id, a.ID)
		if err != nil {
			h.logger.Error("admin: list inherited groups (bulk)", "user_id", id, "app_id", a.ID, "error", err)
			hadErr = true
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
			hadErr = true
			continue
		}
		currentGroupSet := make(map[string]bool, len(currentGroups))
		for _, g := range currentGroups {
			currentGroupSet[g.ID] = true
			if !desiredGroups[g.ID] && !inheritedSet[g.ID] {
				if err := h.apps.UnassignUserGroup(ctx, id, a.ID, g.ID); err != nil {
					h.logger.Error("admin: unassign user group (bulk)", "user_id", id, "app_id", a.ID, "group_id", g.ID, "error", err)
					hadErr = true
				} else {
					assignmentsChanged = true
				}
			}
		}
		for gid := range desiredGroups {
			if !currentGroupSet[gid] {
				if err := h.apps.AssignUserGroup(ctx, id, a.ID, gid); err != nil {
					h.logger.Error("admin: assign user group (bulk)", "user_id", id, "app_id", a.ID, "group_id", gid, "error", err)
					hadErr = true
				} else {
					assignmentsChanged = true
				}
			}
		}
	}

	if assignmentsChanged {
		h.logAudit(r, AuditActionAppAssignmentsUpdate, "user", targetUser.ID, targetUser.Username)
	}
	if hadErr {
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s/apps?flash=error", id), http.StatusFound)
		return
	}
	// No success flash: the updated checkbox state is the feedback.
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%s/apps", id), http.StatusFound)
}
