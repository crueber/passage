package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/app"
)

// policyForm returns a minimal valid create/update form with the policy fields
// applied on top.
func policyForm(slug, name string, policy map[string]string) url.Values {
	form := url.Values{}
	form.Set("slug", slug)
	form.Set("name", name)
	form.Set("is_active", "on")
	for k, v := range policy {
		form.Set(k, v)
	}
	return form
}

// TestAdminApps_Create_Policy saves a full policy and verifies it round-trips
// through the store, and that an app created with every policy field empty
// behaves exactly as before (all zero values).
func TestAdminApps_Create_Policy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		slug   string
		policy map[string]string
		want   app.App
	}{
		{
			name: "all fields empty keeps the previous behaviour",
			slug: "policy-empty",
			want: app.App{},
		},
		{
			name: "full policy is stored",
			slug: "policy-full",
			policy: map[string]string{
				"required_group": "platform",
				"required_role":  "ops",
				"allowed_cidrs":  "192.168.0.0/16, 2001:db8::/32",
				"admin_only":     "on",
				"allowed_hours":  "09:00-17:00",
				"allowed_days":   "1-5,7",
			},
			want: app.App{
				RequiredGroup: "platform",
				RequiredRole:  "ops",
				AllowedCIDRs:  "192.168.0.0/16, 2001:db8::/32",
				AdminOnly:     true,
				AllowedHours:  "09:00-17:00",
				AllowedDays:   "1-5,7",
			},
		},
		{
			name: "overnight window is accepted",
			slug: "policy-overnight",
			policy: map[string]string{
				"allowed_hours": "22:00-06:00",
			},
			want: app.App{AllowedHours: "22:00-06:00"},
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

			form := policyForm(tc.slug, "Policy App", tc.policy)
			rec := adminRequest(t, router, http.MethodPost, "/admin/apps", token, f.cfg.Session.CookieName,
				strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
			if got := rec.Result().StatusCode; got != http.StatusFound {
				t.Fatalf("create: status %d, want 302; body: %s", got, rec.Body.String())
			}

			stored, err := f.appStore.GetBySlug(ctx, tc.slug)
			if err != nil {
				t.Fatalf("get created app: %v", err)
			}
			if stored.RequiredGroup != tc.want.RequiredGroup ||
				stored.RequiredRole != tc.want.RequiredRole ||
				stored.AllowedCIDRs != tc.want.AllowedCIDRs ||
				stored.AdminOnly != tc.want.AdminOnly ||
				stored.AllowedHours != tc.want.AllowedHours ||
				stored.AllowedDays != tc.want.AllowedDays {
				t.Errorf("stored policy = %+v, want %+v", stored.Policy(), tc.want.Policy())
			}
		})
	}
}

// TestAdminApps_Create_PolicyValidation pins that garbage in any policy field
// re-renders the form with the existing error style and does not create the app.
func TestAdminApps_Create_PolicyValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		policy    map[string]string
		wantInMsg string
	}{
		{
			name:      "invalid cidr",
			policy:    map[string]string{"allowed_cidrs": "192.0.2.1"},
			wantInMsg: "Access policy:",
		},
		{
			name:      "invalid cidr prefix length",
			policy:    map[string]string{"allowed_cidrs": "10.0.0.0/33"},
			wantInMsg: "allowed cidrs",
		},
		{
			name:      "invalid hours",
			policy:    map[string]string{"allowed_hours": "9am-5pm"},
			wantInMsg: "allowed hours",
		},
		{
			name:      "invalid hours range",
			policy:    map[string]string{"allowed_hours": "09:00-25:00"},
			wantInMsg: "allowed hours",
		},
		{
			name:      "invalid days",
			policy:    map[string]string{"allowed_days": "mon-fri"},
			wantInMsg: "allowed days",
		},
		{
			name:      "invalid day number",
			policy:    map[string]string{"allowed_days": "8"},
			wantInMsg: "allowed days",
		},
		{
			name: "multiple invalid fields are reported together",
			policy: map[string]string{
				"allowed_cidrs": "nope",
				"allowed_days":  "0",
			},
			wantInMsg: "allowed cidrs",
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

			form := policyForm("policy-invalid", "Policy Invalid", tc.policy)
			rec := adminRequest(t, router, http.MethodPost, "/admin/apps", token, f.cfg.Session.CookieName,
				strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
			if got := rec.Result().StatusCode; got != http.StatusOK {
				t.Fatalf("status = %d, want 200 (re-render); body: %s", got, rec.Body.String())
			}
			body := rec.Body.String()
			if !strings.Contains(body, tc.wantInMsg) {
				t.Errorf("body does not contain %q: %s", tc.wantInMsg, body)
			}

			// The form must re-render the submitted value so the admin can fix
			// it, and no app may have been created.
			for field, value := range tc.policy {
				if field == "admin_only" {
					continue
				}
				if !strings.Contains(body, value) {
					t.Errorf("re-rendered form lost the submitted %s value %q", field, value)
				}
			}
			if _, err := f.appStore.GetBySlug(ctx, "policy-invalid"); err == nil {
				t.Error("invalid policy created an app, want no app")
			}
		})
	}
}

// TestAdminApps_Update_Policy saves a policy over an existing app and rejects
// an invalid one without changing what is stored.
func TestAdminApps_Update_Policy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	if err := f.appSvc.Create(ctx, &app.App{
		Slug:        "policy-update",
		Name:        "Policy Update",
		HostPattern: "policy-update.example.com",
		IsActive:    true,
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	created, err := f.appStore.GetBySlug(ctx, "policy-update")
	if err != nil {
		t.Fatalf("get app: %v", err)
	}

	// Save a valid policy.
	form := policyForm("policy-update", "Policy Update", map[string]string{
		"required_group": "platform",
		"allowed_cidrs":  "10.0.0.0/8",
		"admin_only":     "on",
		"allowed_hours":  "08:30-18:00",
		"allowed_days":   "1-5",
	})
	rec := adminRequest(t, router, http.MethodPost, "/admin/apps/"+created.ID, token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if got := rec.Result().StatusCode; got != http.StatusFound {
		t.Fatalf("update: status %d, want 302; body: %s", got, rec.Body.String())
	}

	stored, err := f.appStore.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get updated app: %v", err)
	}
	if stored.RequiredGroup != "platform" || stored.AllowedCIDRs != "10.0.0.0/8" || !stored.AdminOnly ||
		stored.AllowedHours != "08:30-18:00" || stored.AllowedDays != "1-5" {
		t.Errorf("stored policy = %+v, want the submitted values", stored.Policy())
	}

	// An invalid update is rejected and the stored policy is untouched.
	badForm := policyForm("policy-update", "Policy Update", map[string]string{
		"required_group": "platform",
		"allowed_days":   "someday",
	})
	rec = adminRequest(t, router, http.MethodPost, "/admin/apps/"+created.ID, token, f.cfg.Session.CookieName,
		strings.NewReader(badForm.Encode()), "application/x-www-form-urlencoded")
	if got := rec.Result().StatusCode; got != http.StatusOK {
		t.Fatalf("invalid update: status %d, want 200 (re-render)", got)
	}
	if !strings.Contains(rec.Body.String(), "allowed days") {
		t.Errorf("invalid update body does not name the field: %s", rec.Body.String())
	}

	after, err := f.appStore.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get app after rejected update: %v", err)
	}
	if after.AllowedDays != "1-5" {
		t.Errorf("rejected update changed allowed_days to %q, want 1-5", after.AllowedDays)
	}
}

// TestAdminApps_EditForm_RendersPolicy pins the form contract: every policy
// input exists, the stored values are rendered, and the help text explains the
// empty-means-unrestricted rule.
func TestAdminApps_EditForm_RendersPolicy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	if err := f.appSvc.Create(ctx, &app.App{
		Slug:          "policy-render",
		Name:          "Policy Render",
		HostPattern:   "policy-render.example.com",
		IsActive:      true,
		RequiredGroup: "platform",
		RequiredRole:  "ops",
		AllowedCIDRs:  "10.0.0.0/8",
		AdminOnly:     true,
		AllowedHours:  "09:00-17:00",
		AllowedDays:   "1-5",
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	created, err := f.appStore.GetBySlug(ctx, "policy-render")
	if err != nil {
		t.Fatalf("get app: %v", err)
	}

	rec := adminRequest(t, router, http.MethodGet, "/admin/apps/"+created.ID, token, f.cfg.Session.CookieName, nil, "")
	if got := rec.Result().StatusCode; got != http.StatusOK {
		t.Fatalf("edit form: status %d, want 200", got)
	}
	body := rec.Body.String()

	for _, field := range []string{"required_group", "required_role", "allowed_cidrs", "allowed_hours", "allowed_days"} {
		if !strings.Contains(body, `name="`+field+`"`) {
			t.Errorf("edit form is missing the %s input", field)
		}
	}
	if !strings.Contains(body, `name="admin_only"`) {
		t.Error("edit form is missing the admin_only checkbox")
	}
	for _, value := range []string{"platform", "ops", "10.0.0.0/8", "09:00-17:00", "1-5"} {
		if !strings.Contains(body, value) {
			t.Errorf("edit form does not render the stored value %q", value)
		}
	}
	if !strings.Contains(body, "Access policy") {
		t.Error("edit form is missing the access policy section")
	}
}
