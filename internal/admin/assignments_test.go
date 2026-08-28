package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/user"
)

// createAssignmentFixtures seeds an app, a user with access, a group, and a
// role, all wired through the fixture. Returns their IDs.
type assignmentFixtures struct {
	appID   string
	userID  string
	groupID string
	roleID  string
	token   string
	router  http.Handler
}

func createAssignmentFixtures(t *testing.T, f *fixture, slug string) assignmentFixtures {
	t.Helper()
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	a := &app.App{Slug: slug, Name: "App " + slug, HostPattern: slug + ".example.com", IsActive: true}
	if err := f.appSvc.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}

	u := &user.User{Username: "assignee", Email: "assignee@example.com", IsActive: true}
	if err := f.userStore.Create(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := f.appSvc.GrantAccess(ctx, u.ID, a.ID); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	g := &app.Group{AppID: a.ID, Name: "test-group"}
	if err := f.appSvc.CreateGroup(ctx, g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	ro := &app.Role{AppID: a.ID, Name: "test-role"}
	if err := f.appSvc.CreateRole(ctx, ro); err != nil {
		t.Fatalf("create role: %v", err)
	}

	return assignmentFixtures{
		appID: a.ID, userID: u.ID, groupID: g.ID, roleID: ro.ID,
		token: token, router: router,
	}
}

// postForm submits a form with the given values to the assignment or role
// edit endpoint and returns the response.
func postForm(t *testing.T, router http.Handler, path, token string, values url.Values) *http.Response {
	t.Helper()
	rec := adminRequest(t, router, http.MethodPost, path, token, "passage_session",
		strings.NewReader(values.Encode()), "application/x-www-form-urlencoded")
	return rec.Result()
}

func TestRoleGroupMembershipViaEditForm(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	fx := createAssignmentFixtures(t, f, "rolegroup-app")
	ctx := context.Background()

	// Edit page renders the group checkbox.
	res := adminRequest(t, fx.router, http.MethodGet,
		"/admin/apps/"+fx.appID+"/roles/"+fx.roleID+"/edit", fx.token, "passage_session", nil, "").Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("role edit page: got %d, want 200", res.StatusCode)
	}
	body := adminRequest(t, fx.router, http.MethodGet,
		"/admin/apps/"+fx.appID+"/roles/"+fx.roleID+"/edit", fx.token, "passage_session", nil, "").Body.String()
	if !strings.Contains(body, `name="group_ids" value="`+fx.groupID+`"`) {
		t.Error("role edit page: group checkbox missing")
	}

	// Check the group and save.
	values := url.Values{}
	values.Set("name", "test-role")
	values.Set("group_ids", fx.groupID)
	res = postForm(t, fx.router, "/admin/apps/"+fx.appID+"/roles/"+fx.roleID, fx.token, values)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("role update: got %d, want 302", res.StatusCode)
	}

	groups, err := f.appSvc.ListGroupsForRole(ctx, fx.roleID)
	if err != nil || len(groups) != 1 || groups[0].ID != fx.groupID {
		t.Fatalf("role groups after save: %v (%d)", err, len(groups))
	}

	// Uncheck and save: membership removed.
	values = url.Values{}
	values.Set("name", "test-role")
	res = postForm(t, fx.router, "/admin/apps/"+fx.appID+"/roles/"+fx.roleID, fx.token, values)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("role update without groups: got %d, want 302", res.StatusCode)
	}
	groups, err = f.appSvc.ListGroupsForRole(ctx, fx.roleID)
	if err != nil || len(groups) != 0 {
		t.Errorf("role groups after uncheck: %v (%d)", err, len(groups))
	}
}

func TestUserAssignmentsPage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	fx := createAssignmentFixtures(t, f, "assignpage-app")
	ctx := context.Background()
	base := "/admin/apps/" + fx.appID + "/access/" + fx.userID + "/assignments"

	// Page renders with both checkboxes.
	res := adminRequest(t, fx.router, http.MethodGet, base, fx.token, "passage_session", nil, "").Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("assignments page: got %d, want 200", res.StatusCode)
	}
	body := adminRequest(t, fx.router, http.MethodGet, base, fx.token, "passage_session", nil, "").Body.String()
	if !strings.Contains(body, `name="role_ids" value="`+fx.roleID+`"`) ||
		!strings.Contains(body, `name="group_ids" value="`+fx.groupID+`"`) {
		t.Error("assignments page: checkboxes missing")
	}

	// Assign both.
	values := url.Values{}
	values.Add("group_ids", fx.groupID)
	values.Add("role_ids", fx.roleID)
	res = postForm(t, fx.router, base, fx.token, values)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("save assignments: got %d, want 302", res.StatusCode)
	}

	direct, err := f.appSvc.ListUserDirectGroups(ctx, fx.userID, fx.appID)
	if err != nil || len(direct) != 1 {
		t.Fatalf("direct groups after save: %v (%d)", err, len(direct))
	}
	roles, err := f.appSvc.ListUserRoles(ctx, fx.userID, fx.appID)
	if err != nil || len(roles) != 1 {
		t.Fatalf("user roles after save: %v (%d)", err, len(roles))
	}

	// Audit event recorded.
	if !hasAuditEvent(f, "app.assignments.update") {
		t.Error("save assignments: no audit event")
	}

	// Unassign everything.
	res = postForm(t, fx.router, base, fx.token, url.Values{})
	if res.StatusCode != http.StatusFound {
		t.Fatalf("clear assignments: got %d, want 302", res.StatusCode)
	}
	direct, err = f.appSvc.ListUserDirectGroups(ctx, fx.userID, fx.appID)
	if err != nil || len(direct) != 0 {
		t.Errorf("direct groups after clear: %v (%d)", err, len(direct))
	}
	roles, err = f.appSvc.ListUserRoles(ctx, fx.userID, fx.appID)
	if err != nil || len(roles) != 0 {
		t.Errorf("roles after clear: %v (%d)", err, len(roles))
	}
}

func TestUserAssignmentsInheritedGroupsReadOnly(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	fx := createAssignmentFixtures(t, f, "inherited-app")
	ctx := context.Background()

	// Role carries the group; user holds only the role.
	if err := f.appSvc.AssignGroupToRole(ctx, fx.roleID, fx.groupID); err != nil {
		t.Fatalf("assign group to role: %v", err)
	}
	if err := f.appSvc.AssignUserRole(ctx, fx.userID, fx.appID, fx.roleID); err != nil {
		t.Fatalf("assign user role: %v", err)
	}

	base := "/admin/apps/" + fx.appID + "/access/" + fx.userID + "/assignments"
	body := adminRequest(t, fx.router, http.MethodGet, base, fx.token, "passage_session", nil, "").Body.String()

	// The inherited group appears once as an unchecked direct checkbox...
	// and the inherited section must render it as a tag.
	if !strings.Contains(body, "Inherited groups") || !strings.Contains(body, "tag is-info") {
		t.Error("assignments page: inherited groups section missing")
	}
	// Saving with the role still checked but NO group_ids must NOT revoke
	// the inherited group: it is not a direct assignment, so the group diff
	// leaves it alone. It survives because the role survives.
	values := url.Values{}
	values.Add("role_ids", fx.roleID)
	res := postForm(t, fx.router, base, fx.token, values)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("save assignments: got %d, want 302", res.StatusCode)
	}
	_, effective, err := f.appSvc.TokenAssignments(ctx, fx.userID, fx.appID)
	if err != nil {
		t.Fatalf("token assignments: %v", err)
	}
	if len(effective) != 1 || effective[0] != "test-group" {
		t.Errorf("effective groups after save without group checkboxes: %v, want [test-group]", effective)
	}

	// Conversely, unchecking the role removes the inherited group too.
	res = postForm(t, fx.router, base, fx.token, url.Values{})
	if res.StatusCode != http.StatusFound {
		t.Fatalf("save assignments clearing roles: got %d, want 302", res.StatusCode)
	}
	_, effective, err = f.appSvc.TokenAssignments(ctx, fx.userID, fx.appID)
	if err != nil {
		t.Fatalf("token assignments after role uncheck: %v", err)
	}
	if len(effective) != 0 {
		t.Errorf("effective groups after role uncheck: %v, want empty", effective)
	}
}
