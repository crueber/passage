package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/crueber/passage/internal/app"
)

// TestService_EvaluateAccess covers the glue between the stored app policy and
// internal/policy: effective group and role names come from the same
// assignment queries that feed OIDC claims, and an app with no policy allows
// without a user.
func TestService_EvaluateAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  func(a *app.App) // mutates the app's policy fields
		setup   func(t *testing.T, svc *testServices, appID, userID string)
		isAdmin bool
		ip      string
		want    bool
		reason  string
		wantErr bool
	}{
		{
			name: "empty policy allows",
			want: true,
		},
		{
			name:   "required group held directly",
			policy: func(a *app.App) { a.RequiredGroup = "platform" },
			setup: func(t *testing.T, svc *testServices, appID, userID string) {
				g := seedGroup(t, svc, appID, "platform")
				if err := svc.appSvc.AssignUserGroup(context.Background(), userID, appID, g.ID); err != nil {
					t.Fatalf("AssignUserGroup: %v", err)
				}
			},
			want: true,
		},
		{
			name:   "required group inherited through role",
			policy: func(a *app.App) { a.RequiredGroup = "platform" },
			setup: func(t *testing.T, svc *testServices, appID, userID string) {
				g := seedGroup(t, svc, appID, "platform")
				ro := seedRole(t, svc, appID, "ops")
				if err := svc.appSvc.AssignGroupToRole(context.Background(), ro.ID, g.ID); err != nil {
					t.Fatalf("AssignGroupToRole: %v", err)
				}
				if err := svc.appSvc.AssignUserRole(context.Background(), userID, appID, ro.ID); err != nil {
					t.Fatalf("AssignUserRole: %v", err)
				}
			},
			want: true,
		},
		{
			name:   "required group missing",
			policy: func(a *app.App) { a.RequiredGroup = "platform" },
			want:   false,
			reason: "group",
		},
		{
			name:   "required role held",
			policy: func(a *app.App) { a.RequiredRole = "ops" },
			setup: func(t *testing.T, svc *testServices, appID, userID string) {
				ro := seedRole(t, svc, appID, "ops")
				if err := svc.appSvc.AssignUserRole(context.Background(), userID, appID, ro.ID); err != nil {
					t.Fatalf("AssignUserRole: %v", err)
				}
			},
			want: true,
		},
		{
			name:    "admin only with admin",
			policy:  func(a *app.App) { a.AdminOnly = true },
			isAdmin: true,
			want:    true,
		},
		{
			name:   "admin only without admin",
			policy: func(a *app.App) { a.AdminOnly = true },
			reason: "admin_only",
		},
		{
			name:   "cidr allowed",
			policy: func(a *app.App) { a.AllowedCIDRs = "10.0.0.0/8" },
			ip:     "10.4.5.6",
			want:   true,
		},
		{
			name:   "cidr denied",
			policy: func(a *app.App) { a.AllowedCIDRs = "10.0.0.0/8" },
			ip:     "192.0.2.10",
			reason: "client_ip",
		},
		{
			name:    "malformed stored cidr errors",
			policy:  func(a *app.App) { a.AllowedCIDRs = "not-a-prefix" },
			ip:      "10.0.0.1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			services := newServices(t)

			a := seedApp(t, services.appSvc, "policy-app", "policy.example.com")
			if tt.policy != nil {
				tt.policy(a)
				if err := services.appSvc.Update(ctx, a); err != nil {
					t.Fatalf("Update app policy: %v", err)
				}
			}

			var userID string
			if !a.Policy().IsEmpty() {
				u := seedUser(t, services.userSvc, "policy-user")
				userID = u.ID
			}
			if tt.setup != nil {
				tt.setup(t, services, a.ID, userID)
			}

			got, err := services.appSvc.EvaluateAccess(ctx, a, userID, tt.isAdmin, tt.ip, time.Now())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("EvaluateAccess() = %+v, nil; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("EvaluateAccess: %v", err)
			}
			if got.Allowed != tt.want {
				t.Errorf("allowed = %v, want %v (reason %q)", got.Allowed, tt.want, got.Reason)
			}
			if !tt.want && got.Reason != tt.reason {
				t.Errorf("reason = %q, want %q", got.Reason, tt.reason)
			}
		})
	}
}

// seedGroup creates a named group for the app.
func seedGroup(t *testing.T, svc *testServices, appID, name string) *app.Group {
	t.Helper()
	g := &app.Group{AppID: appID, Name: name}
	if err := svc.appSvc.CreateGroup(context.Background(), g); err != nil {
		t.Fatalf("CreateGroup %q: %v", name, err)
	}
	return g
}

// seedRole creates a named role for the app.
func seedRole(t *testing.T, svc *testServices, appID, name string) *app.Role {
	t.Helper()
	ro := &app.Role{AppID: appID, Name: name}
	if err := svc.appSvc.CreateRole(context.Background(), ro); err != nil {
		t.Fatalf("CreateRole %q: %v", name, err)
	}
	return ro
}
