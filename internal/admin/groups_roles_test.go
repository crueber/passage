package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/app"
)

// createNamedTestApp creates an app via the fixture's service and returns it.
func createNamedTestApp(t *testing.T, f *fixture, slug string) *app.App {
	t.Helper()
	a := &app.App{
		Slug:        slug,
		Name:        "App " + slug,
		HostPattern: slug + ".example.com",
		IsActive:    true,
	}
	if err := f.appSvc.Create(context.Background(), a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	return a
}

// namedItemForm POSTs a name/description form to the given path.
func namedItemForm(t *testing.T, router http.Handler, method, path, token string, name, description string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("name", name)
	form.Set("description", description)
	rec := adminRequest(t, router, method, path, token, "passage_session",
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	return rec.Result()
}

// hasAuditEvent reports whether the fixture's audit log recorded an event
// with the given action.
func hasAuditEvent(f *fixture, action string) bool {
	for _, e := range f.audit.events {
		if e.Action == action {
			return true
		}
	}
	return false
}

func TestAppGroupsCRUD(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	a := createNamedTestApp(t, f, "groups-crud-app")
	base := "/admin/apps/" + a.ID + "/groups"

	// List page renders with empty state.
	res := adminRequest(t, router, http.MethodGet, base, token, "passage_session", nil, "").Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list groups page: got %d, want 200", res.StatusCode)
	}

	// Create a group.
	res = namedItemForm(t, router, http.MethodPost, base, token, "admins", "Admin group")
	if res.StatusCode != http.StatusFound {
		t.Errorf("create group: got %d, want 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "flash=created") {
		t.Errorf("create group: redirect %q missing flash=created", loc)
	}
	groups, err := f.appStore.ListGroupsByApp(context.Background(), a.ID)
	if err != nil || len(groups) != 1 || groups[0].Name != "admins" {
		t.Fatalf("create group: store has %d groups (%v)", len(groups), err)
	}
	groupID := groups[0].ID

	// Duplicate name re-renders with an error, not a redirect.
	res = namedItemForm(t, router, http.MethodPost, base, token, "admins", "")
	if res.StatusCode != http.StatusOK {
		t.Errorf("create duplicate group: got %d, want 200 with error", res.StatusCode)
	}

	// Audit event was recorded for create.
	if !hasAuditEvent(f, "app.group.create") {
		t.Error("create group: no app.group.create audit event")
	}

	// Edit page renders.
	res = adminRequest(t, router, http.MethodGet, base+"/"+groupID+"/edit", token, "passage_session", nil, "").Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("edit group page: got %d, want 200", res.StatusCode)
	}

	// Update.
	res = namedItemForm(t, router, http.MethodPost, base+"/"+groupID, token, "admins", "Updated")
	if res.StatusCode != http.StatusFound {
		t.Errorf("update group: got %d, want 302", res.StatusCode)
	}
	updated, err := f.appStore.GetGroup(context.Background(), groupID)
	if err != nil || updated.Description != "Updated" {
		t.Errorf("update group: description = %q (%v)", updated.Description, err)
	}

	// Delete.
	res = namedItemForm(t, router, http.MethodPost, base+"/"+groupID+"/delete", token, "", "")
	if res.StatusCode != http.StatusFound {
		t.Errorf("delete group: got %d, want 302", res.StatusCode)
	}
	if _, err := f.appStore.GetGroup(context.Background(), groupID); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("delete group: still exists (%v)", err)
	}
}

func TestAppRolesCRUD(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	a := createNamedTestApp(t, f, "roles-crud-app")
	base := "/admin/apps/" + a.ID + "/roles"

	// Create a role.
	res := namedItemForm(t, router, http.MethodPost, base, token, "viewer", "Read-only")
	if res.StatusCode != http.StatusFound {
		t.Errorf("create role: got %d, want 302", res.StatusCode)
	}
	roles, err := f.appStore.ListRolesByApp(context.Background(), a.ID)
	if err != nil || len(roles) != 1 || roles[0].Name != "viewer" {
		t.Fatalf("create role: store has %d roles (%v)", len(roles), err)
	}
	roleID := roles[0].ID

	// List page renders and mentions the role.
	body := adminRequest(t, router, http.MethodGet, base, token, "passage_session", nil, "").Body.String()
	if !strings.Contains(body, "viewer") {
		t.Error("list roles page: body does not contain role name")
	}

	// Update and delete.
	res = namedItemForm(t, router, http.MethodPost, base+"/"+roleID, token, "viewer", "Updated")
	if res.StatusCode != http.StatusFound {
		t.Errorf("update role: got %d, want 302", res.StatusCode)
	}
	res = namedItemForm(t, router, http.MethodPost, base+"/"+roleID+"/delete", token, "", "")
	if res.StatusCode != http.StatusFound {
		t.Errorf("delete role: got %d, want 302", res.StatusCode)
	}
	if _, err := f.appStore.GetRole(context.Background(), roleID); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("delete role: still exists (%v)", err)
	}

	// Audit events.
	if !hasAuditEvent(f, "app.role.create") || !hasAuditEvent(f, "app.role.delete") {
		t.Error("role CRUD: missing audit events")
	}
}

func TestAppNamedItemsUnknownAppRedirects(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	res := adminRequest(t, router, http.MethodGet, "/admin/apps/no-such-app/groups", token, "passage_session", nil, "").Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("groups for unknown app: got %d, want 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/admin/apps" {
		t.Errorf("groups for unknown app: redirect %q, want /admin/apps", loc)
	}
}
