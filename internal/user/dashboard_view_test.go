package user_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// dashboardRequest performs GET / with the signed-in user and optional cookie.
func dashboardRequest(t *testing.T, f *handlerFixture, u *user.User, cookieValue string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: "passage_app_view", Value: cookieValue})
	}
	rec := httptest.NewRecorder()
	f.handler.GetDashboard(rec, req)
	return rec
}

func seedViewApps(t *testing.T, f *handlerFixture, userID string) {
	t.Helper()
	ctx := context.Background()
	for _, a := range []*app.App{
		{Slug: "alpha", Name: "Alpha", Description: "First app", HostPattern: "alpha.lab.local", DefaultURL: "https://alpha.lab.local", IsActive: true},
		{Slug: "bravo", Name: "Bravo", Description: "Second app", HostPattern: "bravo.lab.local", DefaultURL: "https://bravo.lab.local", IsActive: true},
	} {
		if err := f.appSvc.Create(ctx, a); err != nil {
			t.Fatalf("seed app: %v", err)
		}
		if err := f.appSvc.GrantAccess(ctx, userID, a.ID); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}
}

// TestDashboard_AppViewPrecedence pins browser cookie -> account default ->
// Comfortable, and the no-JS ?view= redirect.
func TestDashboard_AppViewPrecedence(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	ctx := context.Background()
	u, err := f.userSvc.Register(ctx, "viewuser", "view@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	seedViewApps(t, f, u.ID)

	if body := dashboardRequest(t, f, u, "").Body.String(); !strings.Contains(body, `data-app-view="comfortable"`) {
		t.Error("default view is not comfortable")
	}

	if err := f.userSvc.UpdateAppView(ctx, u.ID, "iconized"); err != nil {
		t.Fatalf("UpdateAppView: %v", err)
	}
	fresh, err := f.userStore.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if body := dashboardRequest(t, f, fresh, "").Body.String(); !strings.Contains(body, `data-app-view="iconized"`) {
		t.Error("account default iconized was not applied")
	}
	if body := dashboardRequest(t, f, fresh, "comfortable").Body.String(); !strings.Contains(body, `data-app-view="comfortable"`) {
		t.Error("browser cookie did not override the account default")
	}

	// No-JS switch: the query is stored as a browser cookie and redirected away.
	req := httptest.NewRequest(http.MethodGet, "/?view=iconized", nil)
	req = req.WithContext(session.WithUser(req.Context(), fresh))
	rec := httptest.NewRecorder()
	f.handler.GetDashboard(rec, req)
	res := rec.Result()
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/" {
		t.Fatalf("view redirect = %d %q, want 302 /", res.StatusCode, res.Header.Get("Location"))
	}
	var found bool
	for _, c := range res.Cookies() {
		if c.Name == "passage_app_view" && c.Value == "iconized" {
			found = true
		}
	}
	if !found {
		t.Error("?view=iconized did not set the browser cookie")
	}
}

// TestDashboard_CommandAndTiles pins the launcher data and the always-visible
// tile star.
func TestDashboard_CommandAndTiles(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	ctx := context.Background()
	u, err := f.userSvc.Register(ctx, "cmduser", "cmd@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	seedViewApps(t, f, u.ID)
	if _, _, err := f.appSvc.ToggleFavorite(ctx, u.ID, func() string {
		apps, err := f.appSvc.ListAppsForUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("list apps: %v", err)
		}
		return apps[0].ID
	}()); err != nil {
		t.Fatalf("ToggleFavorite: %v", err)
	}

	body := dashboardRequest(t, f, u, "iconized").Body.String()
	for _, want := range []string{
		`id="command-layer"`,
		`id="command-input"`,
		`data-search="alpha alpha alpha.lab.local first app"`,
		`class="tile-favorite`,
		`class="shelf-favorite is-favorite"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	if strings.Contains(body, "Recent") {
		t.Error("command launcher unexpectedly contains a Recent section")
	}
}

// TestDashboard_SingleAppState proves the one-app page uses the solo card in
// Iconized mode and a single row in Comfortable mode.
func TestDashboard_SingleAppState(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	ctx := context.Background()
	u, err := f.userSvc.Register(ctx, "onepage", "one@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	a := &app.App{Slug: "only", Name: "Only App", Description: "The only one", HostPattern: "only.lab.local", DefaultURL: "https://only.lab.local", IsActive: true}
	if err := f.appSvc.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	if err := f.appSvc.GrantAccess(ctx, u.ID, a.ID); err != nil {
		t.Fatalf("grant: %v", err)
	}

	comfortable := dashboardRequest(t, f, u, "comfortable").Body.String()
	if !strings.Contains(comfortable, "Your app") || !strings.Contains(comfortable, "class=\"app-row-main\"") {
		t.Error("single-app Comfortable state is missing its row")
	}
	iconized := dashboardRequest(t, f, u, "iconized").Body.String()
	if !strings.Contains(iconized, "class=\"app-solo\"") {
		t.Error("single-app Iconized state is missing the solo card")
	}
}
