package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// TestService_CrossAppUserAssignmentRejected proves that assigning a group or
// role belonging to app B onto a user under app A is rejected with
// ErrCrossAppAssignment.
func TestService_CrossAppUserAssignmentRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	userStore := user.NewStore(db)
	u := &user.User{Username: "alice", Email: "alice@example.com", IsActive: true, Roles: "[]"}
	if err := userStore.Create(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	store := app.NewStore(db)
	svc := app.NewService(store, store, logger)

	appA := &app.App{Slug: "app-a", Name: "App A", HostPattern: "a.example.com", IsActive: true}
	appB := &app.App{Slug: "app-b", Name: "App B", HostPattern: "b.example.com", IsActive: true}
	if err := svc.Create(ctx, appA); err != nil {
		t.Fatalf("create appA: %v", err)
	}
	if err := svc.Create(ctx, appB); err != nil {
		t.Fatalf("create appB: %v", err)
	}

	groupB := &app.Group{AppID: appB.ID, Name: "editors"}
	roleB := &app.Role{AppID: appB.ID, Name: "maintainer"}
	if err := svc.CreateGroup(ctx, groupB); err != nil {
		t.Fatalf("create groupB: %v", err)
	}
	if err := svc.CreateRole(ctx, roleB); err != nil {
		t.Fatalf("create roleB: %v", err)
	}

	if err := svc.AssignUserGroup(ctx, u.ID, appA.ID, groupB.ID); !errors.Is(err, app.ErrCrossAppAssignment) {
		t.Errorf("AssignUserGroup cross-app error = %v, want ErrCrossAppAssignment", err)
	}
	if err := svc.AssignUserRole(ctx, u.ID, appA.ID, roleB.ID); !errors.Is(err, app.ErrCrossAppAssignment) {
		t.Errorf("AssignUserRole cross-app error = %v, want ErrCrossAppAssignment", err)
	}
}

// TestService_RevokeAccessClearsAssignments verifies that revoking app access
// also removes the user's app-scoped direct groups and roles.
func TestService_RevokeAccessClearsAssignments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	userStore := user.NewStore(db)
	u := &user.User{Username: "bob", Email: "bob@example.com", IsActive: true, Roles: "[]"}
	if err := userStore.Create(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	store := app.NewStore(db)
	svc := app.NewService(store, store, logger)

	a := &app.App{Slug: "grafana", Name: "Grafana", HostPattern: "grafana.example.com", IsActive: true}
	if err := svc.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	g := &app.Group{AppID: a.ID, Name: "viewers"}
	ro := &app.Role{AppID: a.ID, Name: "admin"}
	if err := svc.CreateGroup(ctx, g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := svc.CreateRole(ctx, ro); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := svc.GrantAccess(ctx, u.ID, a.ID); err != nil {
		t.Fatalf("grant access: %v", err)
	}
	if err := svc.AssignUserGroup(ctx, u.ID, a.ID, g.ID); err != nil {
		t.Fatalf("assign group: %v", err)
	}
	if err := svc.AssignUserRole(ctx, u.ID, a.ID, ro.ID); err != nil {
		t.Fatalf("assign role: %v", err)
	}

	if err := svc.RevokeAccess(ctx, u.ID, a.ID); err != nil {
		t.Fatalf("revoke access: %v", err)
	}

	groups, err := svc.ListUserDirectGroups(ctx, u.ID, a.ID)
	if err != nil {
		t.Fatalf("list direct groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("direct groups after revoke = %d, want 0", len(groups))
	}
	roles, err := svc.ListUserRoles(ctx, u.ID, a.ID)
	if err != nil {
		t.Fatalf("list user roles: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("roles after revoke = %d, want 0", len(roles))
	}
}
