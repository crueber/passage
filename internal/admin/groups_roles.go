package admin

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
)

// namedItemRow is the template-facing row for the app groups and roles
// pages. Both entities have identical shape: a name and a description.
type namedItemRow struct {
	ID          string
	Name        string
	Description string
}

// appNamedItemsData backs the shared groups/roles admin page.
type appNamedItemsData struct {
	basePage
	appTabs
	Kind           string // "groups" or "roles"; used in URLs and template branching
	Plural         string // "Groups" or "Roles"; page heading
	Items          []namedItemRow
	IsEdit         bool
	EditItem       *namedItemRow
	AddName        string // preserved input on create failure
	AddDescription string
}

// getAppForAdmin loads the app named by the {id} URL param, writing the
// error response itself. The bool is false when the response is already
// written and the caller must return.
func (h *Handler) getAppForAdmin(w http.ResponseWriter, r *http.Request, purpose string) (*app.App, bool) {
	id := chi.URLParam(r, "id")
	a, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			http.Redirect(w, r, "/admin/apps", http.StatusFound)
			return nil, false
		}
		h.logger.Error("admin: get app for "+purpose, "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}
	return a, true
}

// namedItemBasePath returns the URL prefix for the kind's routes,
// e.g. "/admin/apps/<id>/groups".
func namedItemBasePath(appID, kind string) string {
	return fmt.Sprintf("/admin/apps/%s/%s", appID, kind)
}

func namedItemPlural(kind string) string {
	if kind == "groups" {
		return "Groups"
	}
	return "Roles"
}

// loadNamedItems lists an app's groups or roles as template rows.
func (h *Handler) loadNamedItems(r *http.Request, a *app.App, kind string) ([]namedItemRow, error) {
	var items []namedItemRow
	if kind == "groups" {
		groups, err := h.apps.ListGroupsByApp(r.Context(), a.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			items = append(items, namedItemRow{ID: g.ID, Name: g.Name, Description: g.Description})
		}
		return items, nil
	}
	roles, err := h.apps.ListRolesByApp(r.Context(), a.ID)
	if err != nil {
		return nil, err
	}
	for _, ro := range roles {
		items = append(items, namedItemRow{ID: ro.ID, Name: ro.Name, Description: ro.Description})
	}
	return items, nil
}

// ─── List pages ──────────────────────────────────────────────────────────────

// GetAppGroups renders the app's groups management page.
func (h *Handler) GetAppGroups(w http.ResponseWriter, r *http.Request) {
	h.getAppNamedItems(w, r, "groups")
}

// GetAppRoles renders the app's roles management page.
func (h *Handler) GetAppRoles(w http.ResponseWriter, r *http.Request) {
	h.getAppNamedItems(w, r, "roles")
}

// getAppNamedItems lists the app's groups or roles with an inline add form.
func (h *Handler) getAppNamedItems(w http.ResponseWriter, r *http.Request, kind string) {
	a, ok := h.getAppForAdmin(w, r, kind+" list")
	if !ok {
		return
	}

	items, err := h.loadNamedItems(r, a, kind)
	if err != nil {
		h.logger.Error("admin: list app "+kind, "app_id", a.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.render(w, r, "admin-app-named-items", appNamedItemsData{
		basePage: h.baseFlash(r, "apps", flashFromQuery(r.URL.Query().Get("flash"))),
		appTabs:  appTabs{App: a, ActiveTab: kind},
		Kind:     kind,
		Plural:   namedItemPlural(kind),
		Items:    items,
	})
}

// ─── Create ──────────────────────────────────────────────────────────────────

// PostCreateAppGroup creates a group for the app.
func (h *Handler) PostCreateAppGroup(w http.ResponseWriter, r *http.Request) {
	h.postCreateNamedItem(w, r, "groups")
}

// PostCreateAppRole creates a role for the app.
func (h *Handler) PostCreateAppRole(w http.ResponseWriter, r *http.Request) {
	h.postCreateNamedItem(w, r, "roles")
}

func (h *Handler) postCreateNamedItem(w http.ResponseWriter, r *http.Request, kind string) {
	a, ok := h.getAppForAdmin(w, r, "create "+kind)
	if !ok {
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")
	listURL := namedItemBasePath(a.ID, kind)

	if name == "" {
		h.render(w, r, "admin-app-named-items", h.namedItemsDataWithError(r, a, kind,
			"Name is required.", name, description))
		return
	}

	var err error
	var itemID string
	if kind == "groups" {
		g := &app.Group{AppID: a.ID, Name: name, Description: description}
		err = h.apps.CreateGroup(r.Context(), g)
		itemID = g.ID
	} else {
		ro := &app.Role{AppID: a.ID, Name: name, Description: description}
		err = h.apps.CreateRole(r.Context(), ro)
		itemID = ro.ID
	}
	if err != nil {
		msg := "Failed to create " + kind + "."
		if errors.Is(err, app.ErrNameTaken) {
			msg = "A " + kind[:len(kind)-1] + " with that name already exists for this app."
		}
		h.logger.Error("admin: create "+kind, "app_id", a.ID, "error", err)
		h.render(w, r, "admin-app-named-items", h.namedItemsDataWithError(r, a, kind, msg, name, description))
		return
	}

	h.logAuditNamedItem(r, kind, "create", itemID, name)
	http.Redirect(w, r, listURL+"?flash=created", http.StatusFound)
}

// namedItemsDataWithError rebuilds the list page data with an error flash
// and the submitted values preserved in the add form. Listing errors are
// non-fatal here: the flash message still renders with an empty table.
func (h *Handler) namedItemsDataWithError(r *http.Request, a *app.App, kind, msg, name, description string) appNamedItemsData {
	items, err := h.loadNamedItems(r, a, kind)
	if err != nil {
		h.logger.Error("admin: list app "+kind+" for error page", "app_id", a.ID, "error", err)
	}
	return appNamedItemsData{
		basePage:       h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
		appTabs:        appTabs{App: a, ActiveTab: kind},
		Kind:           kind,
		Plural:         namedItemPlural(kind),
		Items:          items,
		AddName:        name,
		AddDescription: description,
	}
}

// ─── Edit ────────────────────────────────────────────────────────────────────

// GetEditAppGroup renders the group edit form.
func (h *Handler) GetEditAppGroup(w http.ResponseWriter, r *http.Request) {
	h.getEditNamedItem(w, r, "groups")
}

// GetEditAppRole renders the role edit form.
func (h *Handler) GetEditAppRole(w http.ResponseWriter, r *http.Request) {
	h.getEditNamedItem(w, r, "roles")
}

func (h *Handler) getEditNamedItem(w http.ResponseWriter, r *http.Request, kind string) {
	a, ok := h.getAppForAdmin(w, r, "edit "+kind)
	if !ok {
		return
	}

	var item *namedItemRow
	if kind == "groups" {
		g, err := h.apps.GetGroup(r.Context(), chi.URLParam(r, "gid"))
		if err != nil {
			h.getNamedItemFailed(w, r, err, a, kind)
			return
		}
		item = &namedItemRow{ID: g.ID, Name: g.Name, Description: g.Description}
	} else {
		ro, err := h.apps.GetRole(r.Context(), chi.URLParam(r, "gid"))
		if err != nil {
			h.getNamedItemFailed(w, r, err, a, kind)
			return
		}
		item = &namedItemRow{ID: ro.ID, Name: ro.Name, Description: ro.Description}
	}

	h.render(w, r, "admin-app-named-items", appNamedItemsData{
		basePage: h.baseFlash(r, "apps", flashFromQuery(r.URL.Query().Get("flash"))),
		appTabs:  appTabs{App: a, ActiveTab: kind},
		Kind:     kind,
		Plural:   namedItemPlural(kind),
		IsEdit:   true,
		EditItem: item,
	})
}

// getNamedItemFailed handles a lookup failure on the edit page: unknown IDs
// redirect back to the list; other errors render a 500.
func (h *Handler) getNamedItemFailed(w http.ResponseWriter, r *http.Request, err error, a *app.App, kind string) {
	if errors.Is(err, app.ErrNotFound) {
		http.Redirect(w, r, namedItemBasePath(a.ID, kind)+"?flash=error", http.StatusFound)
		return
	}
	h.logger.Error("admin: get "+kind+" item", "app_id", a.ID, "error", err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// ─── Update ──────────────────────────────────────────────────────────────────

// PostUpdateAppGroup updates a group.
func (h *Handler) PostUpdateAppGroup(w http.ResponseWriter, r *http.Request) {
	h.postUpdateNamedItem(w, r, "groups")
}

// PostUpdateAppRole updates a role.
func (h *Handler) PostUpdateAppRole(w http.ResponseWriter, r *http.Request) {
	h.postUpdateNamedItem(w, r, "roles")
}

func (h *Handler) postUpdateNamedItem(w http.ResponseWriter, r *http.Request, kind string) {
	a, ok := h.getAppForAdmin(w, r, "update "+kind)
	if !ok {
		return
	}

	gid := chi.URLParam(r, "gid")
	name := r.FormValue("name")
	description := r.FormValue("description")
	listURL := namedItemBasePath(a.ID, kind)

	if name == "" {
		item := &namedItemRow{ID: gid, Name: name, Description: description}
		h.render(w, r, "admin-app-named-items", h.namedItemsEditDataWithError(r, a, kind,
			"Name is required.", item))
		return
	}

	var err error
	if kind == "groups" {
		err = h.apps.UpdateGroup(r.Context(), &app.Group{ID: gid, Name: name, Description: description})
	} else {
		err = h.apps.UpdateRole(r.Context(), &app.Role{ID: gid, Name: name, Description: description})
	}
	if err != nil {
		msg := "Failed to save " + kind + "."
		if errors.Is(err, app.ErrNameTaken) {
			msg = "A " + kind[:len(kind)-1] + " with that name already exists for this app."
		}
		h.logger.Error("admin: update "+kind, "app_id", a.ID, "gid", gid, "error", err)
		item := &namedItemRow{ID: gid, Name: name, Description: description}
		h.render(w, r, "admin-app-named-items", h.namedItemsEditDataWithError(r, a, kind, msg, item))
		return
	}

	h.logAuditNamedItem(r, kind, "update", gid, name)
	http.Redirect(w, r, listURL+"?flash=updated", http.StatusFound)
}

// namedItemsEditDataWithError rebuilds the edit page data with an error
// flash and the submitted values preserved in the form.
func (h *Handler) namedItemsEditDataWithError(r *http.Request, a *app.App, kind, msg string, item *namedItemRow) appNamedItemsData {
	return appNamedItemsData{
		basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
		appTabs:  appTabs{App: a, ActiveTab: kind},
		Kind:     kind,
		Plural:   namedItemPlural(kind),
		IsEdit:   true,
		EditItem: item,
	}
}

// ─── Delete ──────────────────────────────────────────────────────────────────

// PostDeleteAppGroup deletes a group.
func (h *Handler) PostDeleteAppGroup(w http.ResponseWriter, r *http.Request) {
	h.postDeleteNamedItem(w, r, "groups")
}

// PostDeleteAppRole deletes a role.
func (h *Handler) PostDeleteAppRole(w http.ResponseWriter, r *http.Request) {
	h.postDeleteNamedItem(w, r, "roles")
}

func (h *Handler) postDeleteNamedItem(w http.ResponseWriter, r *http.Request, kind string) {
	a, ok := h.getAppForAdmin(w, r, "delete "+kind)
	if !ok {
		return
	}

	gid := chi.URLParam(r, "gid")
	listURL := namedItemBasePath(a.ID, kind)

	var name string
	if kind == "groups" {
		if g, err := h.apps.GetGroup(r.Context(), gid); err == nil {
			name = g.Name
		}
		if err := h.apps.DeleteGroup(r.Context(), gid); err != nil {
			h.deleteNamedItemFailed(w, r, err, a, kind, gid)
			return
		}
	} else {
		if ro, err := h.apps.GetRole(r.Context(), gid); err == nil {
			name = ro.Name
		}
		if err := h.apps.DeleteRole(r.Context(), gid); err != nil {
			h.deleteNamedItemFailed(w, r, err, a, kind, gid)
			return
		}
	}

	h.logAuditNamedItem(r, kind, "delete", gid, name)
	http.Redirect(w, r, listURL+"?flash=deleted", http.StatusFound)
}

// deleteNamedItemFailed handles delete failures: unknown IDs redirect back
// with an error flash; other errors render a 500.
func (h *Handler) deleteNamedItemFailed(w http.ResponseWriter, r *http.Request, err error, a *app.App, kind, gid string) {
	if errors.Is(err, app.ErrNotFound) {
		http.Redirect(w, r, namedItemBasePath(a.ID, kind)+"?flash=error", http.StatusFound)
		return
	}
	h.logger.Error("admin: delete "+kind, "app_id", a.ID, "gid", gid, "error", err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// ─── Audit ───────────────────────────────────────────────────────────────────

// namedItemAuditActions maps kind+action to the audit action constant.
var namedItemAuditActions = map[string]string{
	"groups.create": AuditActionAppGroupCreate,
	"groups.update": AuditActionAppGroupUpdate,
	"groups.delete": AuditActionAppGroupDelete,
	"roles.create":  AuditActionAppRoleCreate,
	"roles.update":  AuditActionAppRoleUpdate,
	"roles.delete":  AuditActionAppRoleDelete,
}

// logAuditNamedItem records an audit event for a group/role CRUD action.
func (h *Handler) logAuditNamedItem(r *http.Request, kind, action, itemID, name string) {
	target := kind[:len(kind)-1] // "group" or "role"
	h.logAudit(r, namedItemAuditActions[kind+"."+action], target, itemID, name)
}
