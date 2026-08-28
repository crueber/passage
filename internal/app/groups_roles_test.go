package app_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/testutil"
)

// newTestAppStore creates a store backed by an in-memory SQLite database.
func newTestAppStore(t *testing.T) *app.SQLiteStore {
	t.Helper()
	return app.NewStore(testutil.NewTestDB(t))
}

// createTestApp inserts an app directly via the store and returns it.
func createTestApp(t *testing.T, s *app.SQLiteStore, slug string) *app.App {
	t.Helper()
	a := &app.App{
		Slug:        slug,
		Name:        "App " + slug,
		HostPattern: slug + ".example.com",
		IsActive:    true,
	}
	if err := s.Create(context.Background(), a); err != nil {
		t.Fatalf("create test app: %v", err)
	}
	return a
}

func TestGroupCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newTestAppStore(t)
	a := createTestApp(t, store, "groups-app")

	// Create.
	g := &app.Group{AppID: a.ID, Name: "admins", Description: "Admin group"}
	if err := store.CreateGroup(ctx, g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if g.ID == "" {
		t.Fatal("create group: ID not assigned")
	}

	// Get.
	got, err := store.GetGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	if got.Name != "admins" || got.Description != "Admin group" || got.AppID != a.ID {
		t.Errorf("get group: got %+v", got)
	}

	// Duplicate name for the same app is rejected.
	dup := &app.Group{AppID: a.ID, Name: "admins"}
	if err := store.CreateGroup(ctx, dup); !errors.Is(err, app.ErrNameTaken) {
		t.Errorf("create duplicate group name: got %v, want ErrNameTaken", err)
	}

	// Same name on a different app is fine.
	other := createTestApp(t, store, "groups-app-2")
	if err := store.CreateGroup(ctx, &app.Group{AppID: other.ID, Name: "admins"}); err != nil {
		t.Errorf("create same group name on other app: %v", err)
	}

	// List, ordered by name.
	if err := store.CreateGroup(ctx, &app.Group{AppID: a.ID, Name: "editors"}); err != nil {
		t.Fatalf("create second group: %v", err)
	}
	groups, err := store.ListGroupsByApp(ctx, a.ID)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(groups) != 2 || groups[0].Name != "admins" || groups[1].Name != "editors" {
		t.Errorf("list groups: got %d groups, want 2 ordered [admins editors]", len(groups))
	}

	// Update.
	got.Description = "Updated description"
	if err := store.UpdateGroup(ctx, got); err != nil {
		t.Fatalf("update group: %v", err)
	}
	updated, err := store.GetGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("get group after update: %v", err)
	}
	if updated.Description != "Updated description" {
		t.Errorf("update group: description = %q", updated.Description)
	}

	// Update of a missing row is ErrNotFound.
	if err := store.UpdateGroup(ctx, &app.Group{ID: "missing-id", Name: "x"}); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("update missing group: got %v, want ErrNotFound", err)
	}

	// Delete.
	if err := store.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("delete group: %v", err)
	}
	if _, err := store.GetGroup(ctx, g.ID); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("get deleted group: got %v, want ErrNotFound", err)
	}
	if err := store.DeleteGroup(ctx, g.ID); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("delete missing group: got %v, want ErrNotFound", err)
	}
}

func TestRoleCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newTestAppStore(t)
	a := createTestApp(t, store, "roles-app")

	// Create.
	ro := &app.Role{AppID: a.ID, Name: "viewer", Description: "Read-only role"}
	if err := store.CreateRole(ctx, ro); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if ro.ID == "" {
		t.Fatal("create role: ID not assigned")
	}

	// Get.
	got, err := store.GetRole(ctx, ro.ID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if got.Name != "viewer" || got.Description != "Read-only role" || got.AppID != a.ID {
		t.Errorf("get role: got %+v", got)
	}

	// Duplicate name for the same app is rejected.
	if err := store.CreateRole(ctx, &app.Role{AppID: a.ID, Name: "viewer"}); !errors.Is(err, app.ErrNameTaken) {
		t.Errorf("create duplicate role name: got %v, want ErrNameTaken", err)
	}

	// List, ordered by name.
	if err := store.CreateRole(ctx, &app.Role{AppID: a.ID, Name: "editor"}); err != nil {
		t.Fatalf("create second role: %v", err)
	}
	roles, err := store.ListRolesByApp(ctx, a.ID)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 2 || roles[0].Name != "editor" || roles[1].Name != "viewer" {
		t.Errorf("list roles: got %d roles, want 2 ordered [editor viewer]", len(roles))
	}

	// Update.
	got.Description = "Updated role"
	if err := store.UpdateRole(ctx, got); err != nil {
		t.Fatalf("update role: %v", err)
	}
	updated, err := store.GetRole(ctx, ro.ID)
	if err != nil {
		t.Fatalf("get role after update: %v", err)
	}
	if updated.Description != "Updated role" {
		t.Errorf("update role: description = %q", updated.Description)
	}

	// Delete.
	if err := store.DeleteRole(ctx, ro.ID); err != nil {
		t.Fatalf("delete role: %v", err)
	}
	if _, err := store.GetRole(ctx, ro.ID); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("get deleted role: got %v, want ErrNotFound", err)
	}
}

func TestGroupsAndRolesCascadeOnAppDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newTestAppStore(t)
	a := createTestApp(t, store, "cascade-app")

	if err := store.CreateGroup(ctx, &app.Group{AppID: a.ID, Name: "g"}); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := store.CreateRole(ctx, &app.Role{AppID: a.ID, Name: "r"}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	if err := store.Delete(ctx, a.ID); err != nil {
		t.Fatalf("delete app: %v", err)
	}

	groups, err := store.ListGroupsByApp(ctx, a.ID)
	if err != nil {
		t.Fatalf("list groups after app delete: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("groups survived app delete: got %d", len(groups))
	}
	roles, err := store.ListRolesByApp(ctx, a.ID)
	if err != nil {
		t.Fatalf("list roles after app delete: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("roles survived app delete: got %d", len(roles))
	}
}

func TestServiceGroupRoleDelegation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newTestAppStore(t)
	svc := app.NewService(store, store, slog.Default())
	a := createTestApp(t, store, "svc-app")

	g := &app.Group{AppID: a.ID, Name: "svc-group"}
	if err := svc.CreateGroup(ctx, g); err != nil {
		t.Fatalf("service create group: %v", err)
	}
	if _, err := svc.GetGroup(ctx, g.ID); err != nil {
		t.Fatalf("service get group: %v", err)
	}
	ro := &app.Role{AppID: a.ID, Name: "svc-role"}
	if err := svc.CreateRole(ctx, ro); err != nil {
		t.Fatalf("service create role: %v", err)
	}
	groups, err := svc.ListGroupsByApp(ctx, a.ID)
	if err != nil || len(groups) != 1 {
		t.Fatalf("service list groups: %v (%d)", err, len(groups))
	}
	roles, err := svc.ListRolesByApp(ctx, a.ID)
	if err != nil || len(roles) != 1 {
		t.Fatalf("service list roles: %v (%d)", err, len(roles))
	}
	g.Name = "svc-group-2"
	if err := svc.UpdateGroup(ctx, g); err != nil {
		t.Fatalf("service update group: %v", err)
	}
	if err := svc.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("service delete group: %v", err)
	}
	if err := svc.DeleteRole(ctx, ro.ID); err != nil {
		t.Fatalf("service delete role: %v", err)
	}
}
