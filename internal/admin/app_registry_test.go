package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/app"
)

// registryForm returns an OAuth-settings form with both registries applied.
func registryForm(scopes, resources string) url.Values {
	return url.Values{
		"scopes":    {scopes},
		"resources": {resources},
	}
}

// TestAdminApps_OAuthRegistry_RoundTrip proves the two textareas are stored as
// newline-separated registries and that empty textareas keep the pre-registry
// behaviour.
func TestAdminApps_OAuthRegistry_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scopes    string
		resources string
		wantScope []string
		wantRes   []string
	}{
		{
			name: "empty means no registry",
		},
		{
			name:      "values round-trip one per line",
			scopes:    "openid\nprofile\nowls:read",
			resources: "https://api.example.com\nurn:example:widget",
			wantScope: []string{"openid", "profile", "owls:read"},
			wantRes:   []string{"https://api.example.com", "urn:example:widget"},
		},
		{
			name:      "blank lines and surrounding spaces are dropped",
			scopes:    "\n openid \n\n profile\n",
			resources: "\n https://api.example.com \n",
			wantScope: []string{"openid", "profile"},
			wantRes:   []string{"https://api.example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			adminUser := createAdminUser(t, f, "admin", "admin@example.com")
			token := createSession(t, f, adminUser.ID)
			router := buildAdminRouter(f)
			ctx := context.Background()
			created := createCoreApp(t, f, router, token, "registry-app", "Registry App")
			form := registryForm(tc.scopes, tc.resources)
			rec := adminRequest(t, router, http.MethodPost, "/admin/apps/"+created.ID+"/oauth-settings", token, f.cfg.Session.CookieName,
				strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
			if got := rec.Result().StatusCode; got != http.StatusFound {
				t.Fatalf("save oauth settings: status %d, want 302; body: %s", got, rec.Body.String())
			}

			stored, err := f.appStore.GetByID(ctx, created.ID)
			if err != nil {
				t.Fatalf("get created app: %v", err)
			}
			if strings.Join(stored.AllowedScopes, ",") != strings.Join(tc.wantScope, ",") {
				t.Errorf("stored scopes = %v, want %v", stored.AllowedScopes, tc.wantScope)
			}
			if strings.Join(stored.AllowedResources, ",") != strings.Join(tc.wantRes, ",") {
				t.Errorf("stored resources = %v, want %v", stored.AllowedResources, tc.wantRes)
			}
		})
	}
}

// TestAdminApps_OAuthRegistry_Validation pins that garbage is rejected with the
// existing error style and no app is created or changed.
func TestAdminApps_OAuthRegistry_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scopes    string
		resources string
		wantInMsg string
	}{
		{name: "scope with a space", scopes: "bad scope", wantInMsg: "OAuth registry:"},
		{name: "scope with punctuation", scopes: "openid!", wantInMsg: "OAuth registry:"},
		{name: "duplicate scope", scopes: "openid\nopenid", wantInMsg: "more than once"},
		{name: "relative resource", resources: "api.example.com", wantInMsg: "absolute URI"},
		{name: "resource with a fragment", resources: "https://api.example.com/x#frag", wantInMsg: "fragment"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			adminUser := createAdminUser(t, f, "admin", "admin@example.com")
			token := createSession(t, f, adminUser.ID)
			router := buildAdminRouter(f)
			created := createCoreApp(t, f, router, token, "registry-invalid", "Registry Invalid")
			form := registryForm(tc.scopes, tc.resources)
			rec := adminRequest(t, router, http.MethodPost, "/admin/apps/"+created.ID+"/oauth-settings", token, f.cfg.Session.CookieName,
				strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
			if got := rec.Result().StatusCode; got != http.StatusOK {
				t.Fatalf("status = %d, want 200 (re-render); body: %s", got, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantInMsg) {
				t.Errorf("body does not contain %q: %s", tc.wantInMsg, rec.Body.String())
			}
		})
	}
}

// TestAdminApps_OAuthRegistry_Update saves a registry over an existing app and
// refuses an invalid one without changing what is stored.
func TestAdminApps_OAuthRegistry_Update(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	if err := f.appSvc.Create(ctx, &app.App{
		Slug:        "registry-update",
		Name:        "Registry Update",
		HostPattern: "registry.example.com",
		IsActive:    true,
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	created, err := f.appStore.GetBySlug(ctx, "registry-update")
	if err != nil {
		t.Fatalf("get app: %v", err)
	}

	form := registryForm("openid\nprofile", "https://api.example.com")
	rec := adminRequest(t, router, http.MethodPost, "/admin/apps/"+created.ID+"/oauth-settings", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if got := rec.Result().StatusCode; got != http.StatusFound {
		t.Fatalf("update: status %d, want 302; body: %s", got, rec.Body.String())
	}

	stored, err := f.appStore.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get updated app: %v", err)
	}
	if len(stored.AllowedScopes) != 2 || stored.AllowedScopes[0] != "openid" ||
		len(stored.AllowedResources) != 1 || stored.AllowedResources[0] != "https://api.example.com" {
		t.Errorf("stored registry = scopes %v resources %v", stored.AllowedScopes, stored.AllowedResources)
	}

	bad := registryForm("openid", "not a uri")
	rec = adminRequest(t, router, http.MethodPost, "/admin/apps/"+created.ID+"/oauth-settings", token, f.cfg.Session.CookieName,
		strings.NewReader(bad.Encode()), "application/x-www-form-urlencoded")
	if got := rec.Result().StatusCode; got != http.StatusOK {
		t.Fatalf("invalid update: status %d, want 200 (re-render)", got)
	}
	if !strings.Contains(rec.Body.String(), "OAuth registry:") {
		t.Errorf("invalid update body does not name the registry: %s", rec.Body.String())
	}

	after, err := f.appStore.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get app after rejected update: %v", err)
	}
	if len(after.AllowedResources) != 1 || after.AllowedResources[0] != "https://api.example.com" {
		t.Errorf("rejected update changed the registry: %v", after.AllowedResources)
	}
}

// TestAdminApps_EditForm_RendersOAuthRegistry pins the form contract: both
// textareas exist and render the stored values.
func TestAdminApps_EditForm_RendersOAuthRegistry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	if err := f.appSvc.Create(ctx, &app.App{
		Slug:             "registry-render",
		Name:             "Registry Render",
		HostPattern:      "registry-render.example.com",
		IsActive:         true,
		AllowedScopes:    []string{"openid", "profile"},
		AllowedResources: []string{"https://api.example.com"},
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	created, err := f.appStore.GetBySlug(ctx, "registry-render")
	if err != nil {
		t.Fatalf("get app: %v", err)
	}

	rec := adminRequest(t, router, http.MethodGet, "/admin/apps/"+created.ID+"/oauth", token, f.cfg.Session.CookieName, nil, "")
	if got := rec.Result().StatusCode; got != http.StatusOK {
		t.Fatalf("edit form: status %d, want 200", got)
	}
	body := rec.Body.String()

	for _, field := range []string{"scopes", "resources"} {
		if !strings.Contains(body, `name="`+field+`"`) {
			t.Errorf("edit form is missing the %s textarea", field)
		}
	}
	for _, value := range []string{"openid", "profile", "https://api.example.com"} {
		if !strings.Contains(body, value) {
			t.Errorf("edit form does not render the stored value %q", value)
		}
	}
	if !strings.Contains(body, "Allowed scopes") || !strings.Contains(body, "Allowed resources (audiences)") {
		t.Error("edit form is missing the OAuth registry labels")
	}
}
