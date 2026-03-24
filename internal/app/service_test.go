package app_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// testServices holds the services needed across app tests.
type testServices struct {
	appSvc  *app.Service
	userSvc *user.Service
}

// newService is a test helper that creates real app and user services backed
// by an in-memory SQLite database. The user service is needed so that tests
// can create real users before calling GrantAccess (the user_app_access table
// enforces a FOREIGN KEY constraint on users.id).
func newService(t *testing.T) (*app.Service, *app.SQLiteStore) {
	t.Helper()
	db := testutil.NewTestDB(t)
	store := app.NewStore(db)
	svc := app.NewService(store, store, slog.Default())
	return svc, store
}

// newServices is a helper that creates both app and user services sharing the
// same in-memory database. Use this when tests need to create real users.
func newServices(t *testing.T) *testServices {
	t.Helper()
	db := testutil.NewTestDB(t)
	appStore := app.NewStore(db)
	appSvc := app.NewService(appStore, appStore, slog.Default())
	userStore := user.NewStore(db)
	cfg := &config.Config{
		Auth: config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
		},
	}
	userSvc := user.NewService(userStore, userStore, cfg)
	return &testServices{appSvc: appSvc, userSvc: userSvc}
}

// seedApp is a test helper that inserts an active app with the given host
// pattern and returns it. Accepts any *app.Service to work with both newService
// and newServices test setups.
func seedApp(t *testing.T, svc *app.Service, slug, hostPattern string) *app.App {
	t.Helper()
	ctx := context.Background()
	a := &app.App{
		Slug:        slug,
		Name:        slug,
		HostPattern: hostPattern,
		IsActive:    true,
	}
	if err := svc.Create(ctx, a); err != nil {
		t.Fatalf("seedApp Create %q: %v", slug, err)
	}
	return a
}

// seedUser is a test helper that registers a user via the user service and
// returns it.
func seedUser(t *testing.T, svc *user.Service, username string) *user.User {
	t.Helper()
	u, err := svc.Register(context.Background(), username, username+"@example.com", "password123")
	if err != nil {
		t.Fatalf("seedUser Register %q: %v", username, err)
	}
	return u
}

// TestResolveFromHost_Exact verifies that an exact hostname match resolves to
// the registered app.
func TestResolveFromHost_Exact(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	want := seedApp(t, svc, "grafana", "grafana.home.example.com")

	got, err := svc.ResolveFromHost(context.Background(), "grafana.home.example.com")
	if err != nil {
		t.Fatalf("ResolveFromHost: unexpected error: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("ResolveFromHost: got app ID %q, want %q", got.ID, want.ID)
	}
}

// TestResolveFromHost_Wildcard verifies that a wildcard pattern like
// "*.home.example.com" matches a specific subdomain.
func TestResolveFromHost_Wildcard(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	want := seedApp(t, svc, "homelab", "*.home.example.com")

	got, err := svc.ResolveFromHost(context.Background(), "grafana.home.example.com")
	if err != nil {
		t.Fatalf("ResolveFromHost: unexpected error: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("ResolveFromHost: got app ID %q, want %q", got.ID, want.ID)
	}
}

// TestResolveFromHost_NoMatch verifies that an unregistered host returns
// ErrNoAppForHost.
func TestResolveFromHost_NoMatch(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	seedApp(t, svc, "grafana", "grafana.home.example.com")

	_, err := svc.ResolveFromHost(context.Background(), "unknown.other.example.com")
	if !errors.Is(err, app.ErrNoAppForHost) {
		t.Errorf("ResolveFromHost: got %v, want ErrNoAppForHost", err)
	}
}

// TestResolveFromHost_StripPort verifies that a host with a port suffix is
// correctly matched after stripping the port.
func TestResolveFromHost_StripPort(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	want := seedApp(t, svc, "grafana", "grafana.home.example.com")

	got, err := svc.ResolveFromHost(context.Background(), "grafana.home.example.com:443")
	if err != nil {
		t.Fatalf("ResolveFromHost: unexpected error: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("ResolveFromHost: got app ID %q, want %q", got.ID, want.ID)
	}
}

// TestResolveFromHost_InactiveApp verifies that an inactive app is not returned
// even if the host pattern matches.
func TestResolveFromHost_InactiveApp(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)

	ctx := context.Background()
	a := &app.App{
		Slug:        "inactive",
		Name:        "Inactive",
		HostPattern: "inactive.home.example.com",
		IsActive:    false,
	}
	if err := svc.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err := svc.ResolveFromHost(ctx, "inactive.home.example.com")
	if !errors.Is(err, app.ErrNoAppForHost) {
		t.Errorf("inactive app: got %v, want ErrNoAppForHost", err)
	}
}

// TestHasAccess verifies the grant → check → revoke → check lifecycle.
func TestHasAccess(t *testing.T) {
	t.Parallel()
	svcs := newServices(t)
	ctx := context.Background()
	a := seedApp(t, svcs.appSvc, "myapp", "myapp.home.example.com")
	u := seedUser(t, svcs.userSvc, "hasaccessuser")

	// Before grant: no access.
	has, err := svcs.appSvc.HasAccess(ctx, u.ID, a.ID)
	if err != nil {
		t.Fatalf("HasAccess (before grant): %v", err)
	}
	if has {
		t.Error("HasAccess before grant: expected false, got true")
	}

	// After grant: access.
	if err := svcs.appSvc.GrantAccess(ctx, u.ID, a.ID); err != nil {
		t.Fatalf("GrantAccess: %v", err)
	}
	has, err = svcs.appSvc.HasAccess(ctx, u.ID, a.ID)
	if err != nil {
		t.Fatalf("HasAccess (after grant): %v", err)
	}
	if !has {
		t.Error("HasAccess after grant: expected true, got false")
	}

	// Double-grant is idempotent (no error).
	if err := svcs.appSvc.GrantAccess(ctx, u.ID, a.ID); err != nil {
		t.Fatalf("GrantAccess (double): %v", err)
	}

	// After revoke: no access.
	if err := svcs.appSvc.RevokeAccess(ctx, u.ID, a.ID); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	has, err = svcs.appSvc.HasAccess(ctx, u.ID, a.ID)
	if err != nil {
		t.Fatalf("HasAccess (after revoke): %v", err)
	}
	if has {
		t.Error("HasAccess after revoke: expected false, got true")
	}
}

// TestListAppsForUser verifies that a user only sees apps they have been
// granted access to.
func TestListAppsForUser(t *testing.T) {
	t.Parallel()
	svcs := newServices(t)
	ctx := context.Background()

	a1 := seedApp(t, svcs.appSvc, "app1", "app1.home.example.com")
	a2 := seedApp(t, svcs.appSvc, "app2", "app2.home.example.com")
	_ = seedApp(t, svcs.appSvc, "app3", "app3.home.example.com")

	u := seedUser(t, svcs.userSvc, "listappsuser")
	if err := svcs.appSvc.GrantAccess(ctx, u.ID, a1.ID); err != nil {
		t.Fatalf("GrantAccess app1: %v", err)
	}
	if err := svcs.appSvc.GrantAccess(ctx, u.ID, a2.ID); err != nil {
		t.Fatalf("GrantAccess app2: %v", err)
	}

	apps, err := svcs.appSvc.ListAppsForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListAppsForUser: %v", err)
	}
	if len(apps) != 2 {
		t.Errorf("ListAppsForUser: got %d apps, want 2", len(apps))
	}
	ids := make(map[string]bool)
	for _, ap := range apps {
		ids[ap.ID] = true
	}
	if !ids[a1.ID] || !ids[a2.ID] {
		t.Errorf("ListAppsForUser: result does not contain both granted apps; got IDs: %v", ids)
	}
}

// TestCreate_SlugUnique verifies that creating two apps with the same slug
// returns ErrSlugTaken.
func TestCreate_SlugUnique(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	ctx := context.Background()

	seedApp(t, svc, "duplicate", "dup1.home.example.com")

	a2 := &app.App{
		Slug:        "duplicate",
		Name:        "Duplicate 2",
		HostPattern: "dup2.home.example.com",
		IsActive:    true,
	}
	err := svc.Create(ctx, a2)
	if !errors.Is(err, app.ErrSlugTaken) {
		t.Errorf("Create duplicate slug: got %v, want ErrSlugTaken", err)
	}
}

// TestValidateHostPattern verifies that ValidateHostPattern is advisory only
// and always returns nil — even for exact duplicates and overlapping patterns.
func TestValidateHostPattern(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name            string
		existingPattern string
		newPattern      string
		overlapExpected bool // documents the intent; ValidateHostPattern always returns nil
	}{
		{
			name:            "exact duplicate pattern",
			existingPattern: "grafana.home.example.com",
			newPattern:      "grafana.home.example.com",
			overlapExpected: true,
		},
		{
			name:            "non-overlapping pattern",
			existingPattern: "grafana.home.example.com",
			newPattern:      "prometheus.other.example.com",
			overlapExpected: false,
		},
		{
			name:            "wildcard matches existing hostname",
			existingPattern: "grafana.home.example.com",
			newPattern:      "*.home.example.com",
			overlapExpected: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Each sub-test gets its own isolated DB so apps don't pollute each other.
			svc, _ := newService(t)
			existing := seedApp(t, svc, "existingapp", tc.existingPattern)

			if tc.overlapExpected {
				t.Logf("overlap expected between existing pattern %q and new pattern %q (advisory only)", tc.existingPattern, tc.newPattern)
			}

			// ValidateHostPattern always returns nil — it is advisory and never blocks creation.
			err := svc.ValidateHostPattern(ctx, tc.newPattern, existing.ID)
			if err != nil {
				t.Errorf("ValidateHostPattern(%q, excludeID=%q): got error %v, want nil", tc.newPattern, existing.ID, err)
			}
		})
	}
}

// TestResolveFromHost_MultiMatch verifies that when two apps both match the
// same host, the one created first (by created_at ASC from ListActive) is
// returned and no error occurs.
func TestResolveFromHost_MultiMatch(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t)
	ctx := context.Background()

	// app1 is created first — it should win on multi-match.
	app1 := seedApp(t, svc, "grafana-exact", "grafana.home.example.com")
	// app2 is a wildcard that also matches "grafana.home.example.com".
	_ = seedApp(t, svc, "homelab-wildcard", "*.home.example.com")

	got, err := svc.ResolveFromHost(ctx, "grafana.home.example.com")
	if err != nil {
		t.Fatalf("ResolveFromHost multi-match: unexpected error: %v", err)
	}
	if got.ID != app1.ID {
		t.Errorf("ResolveFromHost multi-match: got app ID %q (%s), want %q (%s)",
			got.ID, got.Slug, app1.ID, app1.Slug)
	}
}
