package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/idp"
)

// TestAdminUsers_SelfDemotionAndDeactivationForbidden verifies that an admin
// cannot remove their own admin flag or deactivate their own account.
func TestAdminUsers_SelfDemotionAndDeactivationForbidden(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "selfadmin", "selfadmin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	tests := []struct {
		name     string
		isAdmin  string
		isActive string
	}{
		{"demote self", "", "on"},
		{"deactivate self", "on", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{
				"username": {adminUser.Username},
				"email":    {adminUser.Email},
				"name":     {adminUser.Name},
			}
			if tc.isAdmin != "" {
				form.Set("is_admin", tc.isAdmin)
			}
			if tc.isActive != "" {
				form.Set("is_active", tc.isActive)
			}

			rec := adminRequest(t, router, http.MethodPost, "/admin/users/"+adminUser.ID, token, f.cfg.Session.CookieName,
				strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 re-render", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "cannot remove your own administrator role") {
				t.Errorf("expected self-lockout error flash; got body without it")
			}

			reloaded, err := f.userStore.GetByID(context.Background(), adminUser.ID)
			if err != nil {
				t.Fatalf("reload admin: %v", err)
			}
			if !reloaded.IsAdmin || !reloaded.IsActive {
				t.Errorf("admin modified despite guard: is_admin=%v is_active=%v", reloaded.IsAdmin, reloaded.IsActive)
			}
		})
	}
}

// TestAdminFlashesRenderedOnEditSigningKeysAndProviders verifies that ?flash=
// query parameters render on pages that previously dropped them.
func TestAdminFlashesRenderedOnEditSigningKeysAndProviders(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.handler.SetProviderManager(idp.NewProviderStore(f.db, nil))
	adminUser := createAdminUser(t, f, "flashadmin", "flashadmin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	tests := []struct {
		path string
		want string
	}{
		{"/admin/users/" + adminUser.ID + "?flash=self-delete-forbidden", "You cannot delete your own account."},
		{"/admin/signing-keys?flash=key-rotated", "New signing key generated"},
		{"/admin/providers?flash=created", "Created successfully."},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			rec := adminRequest(t, router, http.MethodGet, tc.path, token, f.cfg.Session.CookieName, nil, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: status = %d, want 200", tc.path, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("GET %s: missing flash text %q", tc.path, tc.want)
			}
		})
	}
}

// TestAdminGroups_CrossAppIDORRejected verifies that editing, updating, or
// deleting app B's group through app A's URL is rejected.
func TestAdminGroups_CrossAppIDORRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "idoradmin", "idoradmin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	appA := &app.App{Slug: "idor-a", Name: "IDOR A", HostPattern: "a.idor.test", IsActive: true}
	appB := &app.App{Slug: "idor-b", Name: "IDOR B", HostPattern: "b.idor.test", IsActive: true}
	if err := f.appSvc.Create(ctx, appA); err != nil {
		t.Fatalf("create appA: %v", err)
	}
	if err := f.appSvc.Create(ctx, appB); err != nil {
		t.Fatalf("create appB: %v", err)
	}
	groupB := &app.Group{AppID: appB.ID, Name: "secret-group", Description: "orig"}
	if err := f.appSvc.CreateGroup(ctx, groupB); err != nil {
		t.Fatalf("create groupB: %v", err)
	}

	// Attempt to update app B's group via app A's route.
	form := url.Values{"name": {"hijacked"}, "description": {"pwned"}}
	rec := adminRequest(t, router, http.MethodPost, "/admin/apps/"+appA.ID+"/groups/"+groupB.ID, token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("cross-app update: status=%d loc=%q, want 302 with flash=error", rec.Code, rec.Header().Get("Location"))
	}

	// Attempt to delete app B's group via app A's route.
	rec = adminRequest(t, router, http.MethodPost, "/admin/apps/"+appA.ID+"/groups/"+groupB.ID+"/delete", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("cross-app delete: status=%d loc=%q, want 302 with flash=error", rec.Code, rec.Header().Get("Location"))
	}

	still, err := f.appSvc.GetGroup(ctx, groupB.ID)
	if err != nil {
		t.Fatalf("groupB should still exist: %v", err)
	}
	if still.Name != "secret-group" {
		t.Errorf("groupB name = %q, want %q", still.Name, "secret-group")
	}
}

// TestAdminLogs_FilterFormPreservesTab verifies that the Admin Actions filter
// form uses action="/admin/logs" with a hidden tab input rather than a query
// string in action (which browsers strip on GET submit).
func TestAdminLogs_FilterFormPreservesTab(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "logadmin", "logadmin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	rec := adminRequest(t, router, http.MethodGet, "/admin/logs?tab=admin", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/logs?tab=admin: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/admin/logs"`) {
		t.Errorf("logs form missing clean action=\"/admin/logs\"")
	}
	if !strings.Contains(body, `<input type="hidden" name="tab" value="admin">`) {
		t.Errorf("admin logs form missing hidden tab input")
	}
	if !strings.Contains(body, `value="user.invite"`) {
		t.Errorf("admin logs action dropdown missing dynamic audit actions (e.g. user.invite)")
	}
}
