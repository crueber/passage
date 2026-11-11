package user_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/config"
)

// TestHandler_GetLogin_ProviderButtons pins the login-page contract: one button
// per configured upstream provider, carrying the return path.
func TestHandler_GetLogin_ProviderButtons(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixtureWith(t, true, func(cfg *config.Config) {
		cfg.Auth.Providers = []config.ProviderConfig{
			{Name: "authentik", Label: "Authentik"},
			{Name: "keycloak", Label: "Keycloak"},
		}
	}, noopSender{})

	req := httptest.NewRequest(http.MethodGet, "/login?rd=%2Foauth%2Fauthorize%3Fclient_id%3Dapp", nil)
	rec := httptest.NewRecorder()
	f.handler.GetLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Sign in with Authentik",
		"Sign in with Keycloak",
		`href="/login/oidc/authentik/start?rd=%2Foauth%2Fauthorize%3Fclient_id%3Dapp"`,
		`href="/login/oidc/keycloak/start?rd=%2Foauth%2Fauthorize%3Fclient_id%3Dapp"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q", want)
		}
	}
}

// TestHandler_GetLogin_NoProviderButtons proves an unconfigured provider list
// adds nothing to the page.
func TestHandler_GetLogin_NoProviderButtons(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	f.handler.GetLogin(rec, req)

	if strings.Contains(rec.Body.String(), `href="/login/oidc/`) {
		t.Error("login page rendered a provider button without any configured provider")
	}
}
