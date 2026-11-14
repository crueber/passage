package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/app"
)

// seedUsers registers n ordinary users in addition to the admin, so the list
// has enough rows to paginate.
func seedUsers(t *testing.T, f *fixture, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		username := fmt.Sprintf("pageuser%02d", i)
		if _, err := f.userSvc.Register(context.Background(), username, username+"@example.com", "password123"); err != nil {
			t.Fatalf("register %s: %v", username, err)
		}
	}
}

func TestPagination_Users(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	seedUsers(t, f, 11) // 12 users total
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	t.Run("defaults to ten", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/users", token, f.cfg.Session.CookieName, nil, "")
		body := rec.Body.String()
		for _, want := range []string{"Page 1 of 2", "12 total", "per_page=25", "per_page=100", "page=2"} {
			if !strings.Contains(body, want) {
				t.Errorf("page 1 missing %q", want)
			}
		}
		if strings.Contains(body, "pageuser10") {
			t.Error("page 1 renders a row that belongs on page 2")
		}
	})

	t.Run("second page", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/users?page=2", token, f.cfg.Session.CookieName, nil, "")
		body := rec.Body.String()
		if !strings.Contains(body, "Page 2 of 2") || !strings.Contains(body, "pageuser10") {
			t.Errorf("page 2 missing its rows or pager: %s", body)
		}
	})

	t.Run("twenty-five per page", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/users?per_page=25", token, f.cfg.Session.CookieName, nil, "")
		body := rec.Body.String()
		if !strings.Contains(body, "Page 1 of 1") || !strings.Contains(body, "pageuser10") {
			t.Errorf("per_page=25 did not render every user: %s", body)
		}
	})

	t.Run("invalid values fall back", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/users?per_page=999&page=-4", token, f.cfg.Session.CookieName, nil, "")
		body := rec.Body.String()
		if !strings.Contains(body, "Page 1 of 2") || !strings.Contains(body, "12 total") {
			t.Error("invalid paging values did not fall back to ten/page one")
		}
	})
}

func seedApps(t *testing.T, f *fixture, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		slug := fmt.Sprintf("pageapp%02d", i)
		if err := f.appSvc.Create(context.Background(), &app.App{
			Slug:     slug,
			Name:     fmt.Sprintf("Page App %02d", i),
			IsActive: true,
		}); err != nil {
			t.Fatalf("create %s: %v", slug, err)
		}
	}
}

func TestPagination_Apps(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	seedApps(t, f, 12)
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	t.Run("defaults to ten", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/apps", token, f.cfg.Session.CookieName, nil, "")
		body := rec.Body.String()
		for _, want := range []string{"Page 1 of 2", "12 total", "page=2"} {
			if !strings.Contains(body, want) {
				t.Errorf("page 1 missing %q", want)
			}
		}
		if strings.Contains(body, "Page App 11") {
			t.Error("page 1 renders an app that belongs on page 2")
		}
	})

	t.Run("second page and larger size", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/apps?page=2", token, f.cfg.Session.CookieName, nil, "")
		if body := rec.Body.String(); !strings.Contains(body, "Page 2 of 2") || !strings.Contains(body, "Page App 11") {
			t.Error("page 2 does not render the remaining apps")
		}
		rec = adminRequest(t, router, http.MethodGet, "/admin/apps?per_page=25", token, f.cfg.Session.CookieName, nil, "")
		if body := rec.Body.String(); !strings.Contains(body, "Page 1 of 1") || !strings.Contains(body, "Page App 11") {
			t.Error("per_page=25 does not render every app")
		}
	})
}

func TestPagination_AppAccess(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	ctx := context.Background()

	a := &app.App{Slug: "paged-access", Name: "Paged Access", IsActive: true}
	if err := f.appSvc.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	seedUsers(t, f, 11) // 12 users total, all granted access
	users, err := f.userStore.List(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	for _, u := range users {
		if err := f.appSvc.GrantAccess(ctx, u.ID, a.ID); err != nil {
			t.Fatalf("grant %s: %v", u.Username, err)
		}
	}
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	t.Run("with access defaults to ten", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/apps/"+a.ID+"/access", token, f.cfg.Session.CookieName, nil, "")
		body := rec.Body.String()
		for _, want := range []string{"Page 1 of 2", "12 total", "with_page=2", "per_page=25"} {
			if !strings.Contains(body, want) {
				t.Errorf("access page 1 missing %q", want)
			}
		}
		if strings.Contains(body, "pageuser10") {
			t.Error("with-access page 1 renders a row that belongs on page 2")
		}
	})

	t.Run("second page of with-access", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/apps/"+a.ID+"/access?with_page=2", token, f.cfg.Session.CookieName, nil, "")
		if body := rec.Body.String(); !strings.Contains(body, "Page 2 of 2") || !strings.Contains(body, "pageuser10") {
			t.Error("with-access page 2 does not render the remaining users")
		}
	})

	t.Run("per_page applies to both lists", func(t *testing.T) {
		rec := adminRequest(t, router, http.MethodGet, "/admin/apps/"+a.ID+"/access?per_page=100", token, f.cfg.Session.CookieName, nil, "")
		if body := rec.Body.String(); !strings.Contains(body, "pageuser10") {
			t.Error("per_page=100 did not render every user with access")
		}
	})
}
