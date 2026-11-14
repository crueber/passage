package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// discardLogger returns a logger that discards output.
func discardLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestStores returns app and user stores sharing one in-memory database.
func newTestStores(t *testing.T) (*app.SQLiteStore, *user.SQLiteStore) {
	t.Helper()
	db := testutil.NewTestDB(t)
	return app.NewStore(db), user.NewStore(db)
}

// createTestUserForApp inserts a real user row (FK target for assignments).
func createTestUserForApp(t *testing.T, userStore *user.SQLiteStore, a *app.App) *user.User {
	t.Helper()
	u := &user.User{
		Username: "assignee-" + a.Slug,
		Email:    "assignee@" + a.Slug + ".example.com",
		IsActive: true,
	}
	if err := userStore.Create(context.Background(), u); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return u
}

// createTestGroupAndRole inserts a group and a role for the app.
func createTestGroupAndRole(t *testing.T, store *app.SQLiteStore, a *app.App, groupName, roleName string) (*app.Group, *app.Role) {
	t.Helper()
	ctx := context.Background()
	g := &app.Group{AppID: a.ID, Name: groupName}
	if err := store.CreateGroup(ctx, g); err != nil {
		t.Fatalf("create group %q: %v", groupName, err)
	}
	ro := &app.Role{AppID: a.ID, Name: roleName}
	if err := store.CreateRole(ctx, ro); err != nil {
		t.Fatalf("create role %q: %v", roleName, err)
	}
	return g, ro
}

func TestGroupRoleAssignment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newTestAppStore(t)
	svc := app.NewService(store, store, discardLogger(t))
	a := createTestApp(t, store, "assign-app")
	gA, roX := createTestGroupAndRole(t, store, a, "group-a", "role-x")
	gB, _ := createTestGroupAndRole(t, store, a, "group-b", "role-y")

	// Assign groups to role-x.
	if err := svc.AssignGroupToRole(ctx, roX.ID, gA.ID); err != nil {
		t.Fatalf("assign group-a to role-x: %v", err)
	}
	// Idempotent.
	if err := svc.AssignGroupToRole(ctx, roX.ID, gA.ID); err != nil {
		t.Fatalf("re-assign group-a to role-x: %v", err)
	}

	groups, err := svc.ListGroupsForRole(ctx, roX.ID)
	if err != nil || len(groups) != 1 || groups[0].Name != "group-a" {
		t.Fatalf("list groups for role: %v (%d groups)", err, len(groups))
	}

	// Cross-app assignment is rejected.
	other := createTestApp(t, store, "assign-app-2")
	gOther, _ := createTestGroupAndRole(t, store, other, "other-group", "other-role")
	if err := svc.AssignGroupToRole(ctx, roX.ID, gOther.ID); !errors.Is(err, app.ErrCrossAppAssignment) {
		t.Errorf("cross-app assignment: got %v, want ErrCrossAppAssignment", err)
	}

	// Unassign.
	if err := svc.UnassignGroupFromRole(ctx, roX.ID, gA.ID); err != nil {
		t.Fatalf("unassign group-a: %v", err)
	}
	groups, err = svc.ListGroupsForRole(ctx, roX.ID)
	if err != nil || len(groups) != 0 {
		t.Errorf("after unassign: %v (%d groups)", err, len(groups))
	}
	// Unassigning group-b (never assigned) is a no-op.
	if err := svc.UnassignGroupFromRole(ctx, roX.ID, gB.ID); err != nil {
		t.Errorf("unassign unassigned group: %v", err)
	}
}

func TestUserAssignmentsAndEffectiveGroups(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, userStore := newTestStores(t)
	svc := app.NewService(store, store, discardLogger(t))
	a := createTestApp(t, store, "eff-app")
	u := createTestUserForApp(t, userStore, a)

	gDirect, _ := createTestGroupAndRole(t, store, a, "direct-group", "unused-role")
	gViaRole, roViewer := createTestGroupAndRole(t, store, a, "role-group", "viewer")
	gOther, _ := createTestGroupAndRole(t, store, a, "unassigned-group", "unused-role-2")

	// Assign direct group and a role that carries another group.
	if err := svc.AssignUserGroup(ctx, u.ID, a.ID, gDirect.ID); err != nil {
		t.Fatalf("assign direct group: %v", err)
	}
	if err := svc.AssignUserRole(ctx, u.ID, a.ID, roViewer.ID); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := svc.AssignGroupToRole(ctx, roViewer.ID, gViaRole.ID); err != nil {
		t.Fatalf("assign group to role: %v", err)
	}

	// Direct groups contain only the direct assignment.
	direct, err := svc.ListUserDirectGroups(ctx, u.ID, a.ID)
	if err != nil || len(direct) != 1 || direct[0].Name != "direct-group" {
		t.Fatalf("direct groups: %v (%d)", err, len(direct))
	}

	// Inherited groups contain only the role's group.
	inherited, err := svc.ListUserInheritedGroups(ctx, u.ID, a.ID)
	if err != nil || len(inherited) != 1 || inherited[0].Name != "role-group" {
		t.Fatalf("inherited groups: %v (%d)", err, len(inherited))
	}

	// Effective groups = direct ∪ inherited, sorted, deduplicated.
	roles, groups, err := svc.TokenAssignments(ctx, u.ID, a.ID)
	if err != nil {
		t.Fatalf("token assignments: %v", err)
	}
	if !slices.Equal(roles, []string{"viewer"}) {
		t.Errorf("roles claim: %v, want [viewer]", roles)
	}
	if !slices.Equal(groups, []string{"direct-group", "role-group"}) {
		t.Errorf("effective groups: %v, want [direct-group role-group]", groups)
	}

	// Unassigned group never appears.
	if slices.Contains(groups, gOther.Name) {
		t.Errorf("unassigned group %q leaked into effective groups", gOther.Name)
	}

	// Revoking the role removes its inherited groups from the effective set.
	if err := svc.UnassignUserRole(ctx, u.ID, a.ID, roViewer.ID); err != nil {
		t.Fatalf("unassign role: %v", err)
	}
	_, groups, err = svc.TokenAssignments(ctx, u.ID, a.ID)
	if err != nil {
		t.Fatalf("token assignments after role revoke: %v", err)
	}
	if !slices.Equal(groups, []string{"direct-group"}) {
		t.Errorf("effective groups after role revoke: %v, want [direct-group]", groups)
	}
	inherited, err = svc.ListUserInheritedGroups(ctx, u.ID, a.ID)
	if err != nil || len(inherited) != 0 {
		t.Errorf("inherited after role revoke: %v (%d)", err, len(inherited))
	}
}

func TestUserAssignmentsScopeToApp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, userStore := newTestStores(t)
	svc := app.NewService(store, store, discardLogger(t))
	a1 := createTestApp(t, store, "scope-app-1")
	a2 := createTestApp(t, store, "scope-app-2")
	u := createTestUserForApp(t, userStore, a1)

	g1, _ := createTestGroupAndRole(t, store, a1, "app1-group", "app1-role")
	g2, _ := createTestGroupAndRole(t, store, a2, "app2-group", "app2-role")

	if err := svc.AssignUserGroup(ctx, u.ID, a1.ID, g1.ID); err != nil {
		t.Fatalf("assign to app1: %v", err)
	}

	// The same user has nothing in app2.
	direct, err := svc.ListUserDirectGroups(ctx, u.ID, a2.ID)
	if err != nil || len(direct) != 0 {
		t.Errorf("app2 direct groups: %v (%d), want empty", err, len(direct))
	}
	_, groups, err := svc.TokenAssignments(ctx, u.ID, a2.ID)
	if err != nil || len(groups) != 0 {
		t.Errorf("app2 effective groups: %v (%d), want empty", err, len(groups))
	}

	// Assignments don't leak into the other app's group set.
	if err := svc.AssignUserGroup(ctx, u.ID, a2.ID, g2.ID); err != nil {
		t.Fatalf("assign to app2: %v", err)
	}
	_, groups, err = svc.TokenAssignments(ctx, u.ID, a1.ID)
	if err != nil || slices.Contains(groups, g2.Name) {
		t.Errorf("app2 group leaked into app1 claims: %v (%v)", groups, err)
	}
}

func TestAssignmentCascadeOnGroupDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, userStore := newTestStores(t)
	svc := app.NewService(store, store, discardLogger(t))
	a := createTestApp(t, store, "cascade-assign-app")
	u := createTestUserForApp(t, userStore, a)
	g, ro := createTestGroupAndRole(t, store, a, "doomed-group", "holder-role")

	if err := svc.AssignGroupToRole(ctx, ro.ID, g.ID); err != nil {
		t.Fatalf("assign group to role: %v", err)
	}
	if err := svc.AssignUserRole(ctx, u.ID, a.ID, ro.ID); err != nil {
		t.Fatalf("assign user role: %v", err)
	}

	// Deleting the group removes it from the role and from effective sets.
	if err := svc.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("delete group: %v", err)
	}
	groups, err := svc.ListGroupsForRole(ctx, ro.ID)
	if err != nil || len(groups) != 0 {
		t.Errorf("role still references deleted group: %v (%d)", err, len(groups))
	}
	_, effective, err := svc.TokenAssignments(ctx, u.ID, a.ID)
	if err != nil || len(effective) != 0 {
		t.Errorf("effective groups after group delete: %v (%v)", effective, err)
	}
}
