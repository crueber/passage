package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestGetUsers_ThemeOverride proves an admin's account theme is rendered on the
// admin pages, replacing the removed per-browser appearance picker.
func TestGetUsers_ThemeOverride(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	adminUser := createAdminUser(t, f, "themeadmin", "themeadmin@example.com")
	if err := f.userStore.SetTheme(context.Background(), adminUser.ID, "nord"); err != nil {
		t.Fatalf("SetTheme: %v", err)
	}
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	rec := adminRequest(t, router, http.MethodGet, "/admin/users", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `data-theme="nord"`) {
		t.Error("admin page does not render the account theme")
	}
}
