package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/adminapi"
	"github.com/crueber/passage/internal/csrf"
)

// tokenPattern matches a plaintext API token in rendered HTML.
var tokenPattern = regexp.MustCompile(`pst_[A-Za-z0-9_-]{43}`)

func TestAdminAPITokens_RequiresAdmin(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// An unrelated (non-admin) user must not reach the page.
	plain, err := f.userSvc.Register(context.Background(), "plain", "plain@example.com", "password123")
	if err != nil {
		t.Fatalf("register plain user: %v", err)
	}
	plainToken := createSession(t, f, plain.ID)

	router := buildAdminRouter(f)
	for _, tc := range []struct {
		name   string
		cookie string
	}{
		{"no session", ""},
		{"non-admin session", plainToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := adminRequest(t, router, http.MethodGet, "/admin/api-tokens", tc.cookie, f.cfg.Session.CookieName, nil, "")
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302 redirect to /login", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "/login" {
				t.Errorf("redirect = %q, want /login", loc)
			}
		})
	}
}

func TestAdminAPITokens_CSRFRequired(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	sessionToken := createSession(t, f, adminUser.ID)

	router := buildAdminRouterWithCSRF(f)
	form := url.Values{"name": {"ci"}}
	rec := adminRequest(t, router, http.MethodPost, "/admin/api-tokens",
		sessionToken, f.cfg.Session.CookieName, strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without a CSRF token status = %d, want 403", rec.Code)
	}

	tokens, err := f.apiTokens.List(context.Background())
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("a rejected POST created %d token(s), want 0", len(tokens))
	}
}

func TestAdminAPITokens_CreateShowsTokenOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	sessionToken := createSession(t, f, adminUser.ID)
	csrfToken, err := csrf.GenerateToken(sessionToken)
	if err != nil {
		t.Fatalf("generate csrf token: %v", err)
	}

	router := buildAdminRouterWithCSRF(f)

	// The empty page renders the create form and the empty state.
	rec := adminRequest(t, router, http.MethodGet, "/admin/api-tokens", sessionToken, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "API tokens") || !strings.Contains(body, "No API tokens") {
		t.Fatalf("empty page is missing its heading or empty state:\n%s", body)
	}
	if !strings.Contains(body, `action="/admin/api-tokens"`) {
		t.Errorf("create form does not post to /admin/api-tokens")
	}

	form := url.Values{"_csrf": {csrfToken}, "name": {"grafana exporter"}}
	rec = adminRequest(t, router, http.MethodPost, "/admin/api-tokens",
		sessionToken, f.cfg.Session.CookieName, strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded")

	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200 with the token rendered; body:\n%s", rec.Code, rec.Body.String())
	}
	body = rec.Body.String()
	if !strings.Contains(body, "grafana exporter") {
		t.Error("created token name is not rendered")
	}

	match := tokenPattern.FindString(body)
	if match == "" {
		t.Fatalf("no plaintext token rendered after creation:\n%s", body)
	}
	if !strings.Contains(body, `id="new-api-token"`) {
		t.Error("plaintext token is not in the copy target")
	}
	if !strings.Contains(body, `data-copy="#new-api-token"`) {
		t.Error("plaintext token has no copy button")
	}

	// The token works and is stored only as a hash.
	stored, err := f.apiTokens.List(context.Background())
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored tokens = %d, want 1", len(stored))
	}
	if stored[0].TokenHash == match || strings.Contains(stored[0].TokenHash, match) {
		t.Error("plaintext token was stored instead of its hash")
	}
	if stored[0].TokenHash != adminapi.HashToken(match) {
		t.Error("stored hash does not match the rendered token")
	}
	if _, err := f.apiTokens.Authenticate(context.Background(), match); err != nil {
		t.Fatalf("rendered token does not authenticate: %v", err)
	}

	// Reloading the page shows the token row but never the plaintext again.
	rec = adminRequest(t, router, http.MethodGet, "/admin/api-tokens", sessionToken, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after create status = %d, want 200", rec.Code)
	}
	body = rec.Body.String()
	if !strings.Contains(body, "grafana exporter") {
		t.Error("token row is missing from the list")
	}
	if tokenPattern.MatchString(body) {
		t.Error("plaintext token is rendered again on reload; it must be shown exactly once")
	}

	// The creation is in the audit log, and the token itself never is.
	var audited bool
	for _, e := range f.audit.events {
		if e.Action == admin.AuditActionAPITokenCreate && e.TargetID == stored[0].ID {
			audited = true
			if strings.Contains(e.Detail, match) || strings.Contains(e.TargetName, match) {
				t.Error("audit entry contains the plaintext token")
			}
		}
	}
	if !audited {
		t.Error("no api_token.create audit entry")
	}
}

func TestAdminAPITokens_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	sessionToken := createSession(t, f, adminUser.ID)
	csrfToken, err := csrf.GenerateToken(sessionToken)
	if err != nil {
		t.Fatalf("generate csrf token: %v", err)
	}

	router := buildAdminRouterWithCSRF(f)
	form := url.Values{"_csrf": {csrfToken}, "name": {"   "}}
	rec := adminRequest(t, router, http.MethodPost, "/admin/api-tokens",
		sessionToken, f.cfg.Session.CookieName, strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with a validation error", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Give the token a name") {
		t.Error("empty name did not render a validation message")
	}
	tokens, err := f.apiTokens.List(context.Background())
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("empty name created %d token(s), want 0", len(tokens))
	}
}

func TestAdminAPITokens_Revoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	sessionToken := createSession(t, f, adminUser.ID)
	csrfToken, err := csrf.GenerateToken(sessionToken)
	if err != nil {
		t.Fatalf("generate csrf token: %v", err)
	}

	plaintext, token, err := f.apiTokens.Create(ctx, "ci")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := buildAdminRouterWithCSRF(f)

	// The active token renders a revoke action with a confirmation.
	rec := adminRequest(t, router, http.MethodGet, "/admin/api-tokens", sessionToken, f.cfg.Session.CookieName, nil, "")
	body := rec.Body.String()
	if !strings.Contains(body, "/admin/api-tokens/"+token.ID+"/revoke") {
		t.Fatalf("active token has no revoke form")
	}
	if !strings.Contains(body, `data-confirm="Revoke this API token?`) {
		t.Error("revoke button has no confirmation prompt")
	}

	form := url.Values{"_csrf": {csrfToken}}
	rec = adminRequest(t, router, http.MethodPost, "/admin/api-tokens/"+token.ID+"/revoke",
		sessionToken, f.cfg.Session.CookieName, strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded")
	if rec.Code != http.StatusFound {
		t.Fatalf("revoke status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/api-tokens?flash=api-token-revoked" {
		t.Errorf("revoke redirect = %q", loc)
	}

	// The token no longer authenticates.
	if _, err := f.apiTokens.Authenticate(ctx, plaintext); err == nil {
		t.Fatal("revoked token still authenticates")
	}

	// The row stays visible as revoked, and the audit log records the action.
	rec = adminRequest(t, router, http.MethodGet, "/admin/api-tokens", sessionToken, f.cfg.Session.CookieName, nil, "")
	body = rec.Body.String()
	if !strings.Contains(body, ">Revoked</span>") {
		t.Error("revoked token is not marked as revoked")
	}
	if strings.Contains(body, "/admin/api-tokens/"+token.ID+"/revoke") {
		t.Error("revoked token still offers a revoke action")
	}

	var audited bool
	for _, e := range f.audit.events {
		if e.Action == admin.AuditActionAPITokenRevoke && e.TargetID == token.ID {
			audited = true
		}
	}
	if !audited {
		t.Error("no api_token.revoke audit entry")
	}
}

func TestAdminAPITokens_RevokeUnknownToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	sessionToken := createSession(t, f, adminUser.ID)
	csrfToken, err := csrf.GenerateToken(sessionToken)
	if err != nil {
		t.Fatalf("generate csrf token: %v", err)
	}

	router := buildAdminRouterWithCSRF(f)
	form := url.Values{"_csrf": {csrfToken}}
	rec := adminRequest(t, router, http.MethodPost, "/admin/api-tokens/no-such-token/revoke",
		sessionToken, f.cfg.Session.CookieName, strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded")

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/api-tokens?flash=error" {
		t.Errorf("redirect = %q, want the error flash", loc)
	}
}
