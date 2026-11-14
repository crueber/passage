package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/idp"
)

// auditContains reports whether the fixture's audit recorder saw an action.
func auditContains(f *fixture, action string) bool {
	for _, e := range f.audit.events {
		if e.Action == action {
			return true
		}
	}
	return false
}

// withProviders wires a real provider store into the admin fixture.
func withProviders(t *testing.T, f *fixture) *idp.ProviderStore {
	t.Helper()
	store := idp.NewProviderStore(f.db, nil)
	f.handler.SetProviderManager(store)
	return store
}

func providerForm() url.Values {
	form := url.Values{}
	form.Set("name", "authentik")
	form.Set("label", "Authentik")
	form.Set("issuer", "https://auth.example.com/application/o/passage/")
	form.Set("client_id", "passage")
	form.Set("client_secret", "s3cret")
	form.Set("scopes", "openid\nemail")
	form.Set("auto_create", "on")
	return form
}

func TestAdminProviders_ListAndEmptyState(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	store := withProviders(t, f)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	body := adminRequest(t, router, http.MethodGet, "/admin/providers", token, f.cfg.Session.CookieName, nil, "").Body.String()
	if !strings.Contains(body, "No upstream providers yet") {
		t.Error("empty state missing")
	}

	if err := store.Create(context.Background(), &idp.Provider{
		Name: "authentik", Issuer: "https://auth.example.com/", ClientID: "passage", ClientSecret: "x",
	}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	body = adminRequest(t, router, http.MethodGet, "/admin/providers", token, f.cfg.Session.CookieName, nil, "").Body.String()
	for _, want := range []string{"authentik", "https://auth.example.com/", "Link only"} {
		if !strings.Contains(body, want) {
			t.Errorf("list missing %q", want)
		}
	}
}

func TestAdminProviders_Create(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	store := withProviders(t, f)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	rec := adminRequest(t, router, http.MethodPost, "/admin/providers", token, f.cfg.Session.CookieName,
		strings.NewReader(providerForm().Encode()), "application/x-www-form-urlencoded")
	if rec.Result().StatusCode != http.StatusFound {
		t.Fatalf("status = %d; want 302 (%s)", rec.Result().StatusCode, rec.Body.String())
	}
	if loc := rec.Result().Header.Get("Location"); !strings.Contains(loc, "flash=created") {
		t.Errorf("redirect = %q", loc)
	}

	list, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Name != "authentik" || !list[0].AutoCreate {
		t.Fatalf("stored providers = %+v", list)
	}
	if !auditContains(f, "provider.create") {
		t.Error("provider.create was not audited")
	}
}

func TestAdminProviders_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(url.Values)
		want   string
	}{
		{name: "http issuer", mutate: func(v url.Values) { v.Set("issuer", "http://idp.example.com") }, want: "issuer must use https"},
		{name: "bad slug", mutate: func(v url.Values) { v.Set("name", "Authentik") }, want: "lowercase slug"},
		{name: "no openid", mutate: func(v url.Values) { v.Set("scopes", "email") }, want: "must include"},
		{name: "missing secret", mutate: func(v url.Values) { v.Del("client_secret") }, want: "client secret must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			store := withProviders(t, f)
			adminUser := createAdminUser(t, f, "admin", "admin@example.com")
			token := createSession(t, f, adminUser.ID)
			router := buildAdminRouter(f)

			form := providerForm()
			tt.mutate(form)
			rec := adminRequest(t, router, http.MethodPost, "/admin/providers", token, f.cfg.Session.CookieName,
				strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
			if rec.Result().StatusCode != http.StatusOK {
				t.Fatalf("status = %d; want 200 (re-render)", rec.Result().StatusCode)
			}
			if !strings.Contains(rec.Body.String(), tt.want) {
				t.Errorf("body missing %q", tt.want)
			}
			list, _ := store.List(context.Background())
			if len(list) != 0 {
				t.Errorf("a rejected form stored %d providers", len(list))
			}
		})
	}
}

func TestAdminProviders_DuplicateName(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	withProviders(t, f)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	for i := 0; i < 2; i++ {
		rec := adminRequest(t, router, http.MethodPost, "/admin/providers", token, f.cfg.Session.CookieName,
			strings.NewReader(providerForm().Encode()), "application/x-www-form-urlencoded")
		if i == 1 {
			if rec.Result().StatusCode != http.StatusOK {
				t.Fatalf("second create status = %d; want 200", rec.Result().StatusCode)
			}
			if !strings.Contains(rec.Body.String(), "already in use") {
				t.Error("duplicate name was not explained")
			}
		}
	}
}

func TestAdminProviders_EditKeepsSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	store := withProviders(t, f)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	p := &idp.Provider{Name: "authentik", Issuer: "https://auth.example.com/", ClientID: "passage", ClientSecret: "original"}
	if err := store.Create(ctx, p); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The edit form must not echo the stored secret.
	body := adminRequest(t, router, http.MethodGet, "/admin/providers/"+p.ID, token, f.cfg.Session.CookieName, nil, "").Body.String()
	if strings.Contains(body, `value="original"`) {
		t.Error("the edit form echoed the stored client secret")
	}

	form := providerForm()
	form.Del("client_secret") // unchanged
	rec := adminRequest(t, router, http.MethodPost, "/admin/providers/"+p.ID, token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if rec.Result().StatusCode != http.StatusFound {
		t.Fatalf("status = %d; want 302 (%s)", rec.Result().StatusCode, rec.Body.String())
	}

	after, err := store.Get(ctx, "authentik")
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if after.ClientSecret != "original" {
		t.Errorf("secret = %q, want the original", after.ClientSecret)
	}
	if after.Label != "Authentik" {
		t.Errorf("label = %q, want the submitted value", after.Label)
	}
}

func TestAdminProviders_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	store := withProviders(t, f)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	p := &idp.Provider{Name: "authentik", Issuer: "https://auth.example.com/", ClientID: "passage", ClientSecret: "x"}
	if err := store.Create(ctx, p); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := adminRequest(t, router, http.MethodPost, "/admin/providers/"+p.ID+"/delete", token,
		f.cfg.Session.CookieName, nil, "")
	if rec.Result().StatusCode != http.StatusFound {
		t.Fatalf("status = %d; want 302", rec.Result().StatusCode)
	}
	if _, err := store.Get(ctx, "authentik"); !errors.Is(err, idp.ErrProviderNotFound) {
		t.Errorf("provider still present after delete: %v", err)
	}
	if !auditContains(f, "provider.delete") {
		t.Error("provider.delete was not audited")
	}
}
