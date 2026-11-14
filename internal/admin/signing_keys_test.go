package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/oauth"
)

// adminSigningKeys returns the stored keys, newest first.
func adminSigningKeys(t *testing.T, f *fixture) []*oauth.SigningKey {
	t.Helper()
	keys, err := f.oauthSvc.ListSigningKeys(context.Background())
	if err != nil {
		t.Fatalf("list signing keys: %v", err)
	}
	return keys
}

// postSigningKeyAction posts an admin form with a valid CSRF token.
func postSigningKeyAction(t *testing.T, f *fixture, router http.Handler, sessionToken, path string) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken, err := csrf.GenerateToken(sessionToken)
	if err != nil {
		t.Fatalf("generate csrf token: %v", err)
	}
	form := url.Values{"_csrf": {csrfToken}}
	return adminRequest(t, router, http.MethodPost, path, sessionToken, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
}

func TestAdminSigningKeys_RequiresAdmin(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	plain, err := f.userSvc.Register(context.Background(), "plain", "plain@example.com", "password123")
	if err != nil {
		t.Fatalf("register plain user: %v", err)
	}
	plainToken := createSession(t, f, plain.ID)

	router := buildAdminRouter(f)
	for _, tc := range []struct {
		name   string
		method string
		path   string
		cookie string
	}{
		{"list without session", http.MethodGet, "/admin/signing-keys", ""},
		{"list as non-admin", http.MethodGet, "/admin/signing-keys", plainToken},
		{"rotate without session", http.MethodPost, "/admin/signing-keys/rotate", ""},
		{"rotate as non-admin", http.MethodPost, "/admin/signing-keys/rotate", plainToken},
		{"retire as non-admin", http.MethodPost, "/admin/signing-keys/some-kid/retire", plainToken},
		{"delete as non-admin", http.MethodPost, "/admin/signing-keys/some-kid/delete", plainToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := adminRequest(t, router, tc.method, tc.path, tc.cookie, f.cfg.Session.CookieName, nil, "")
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302 redirect to /login", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "/login" {
				t.Errorf("redirect = %q, want /login", loc)
			}
		})
	}

	// A rejected request must not have rotated anything.
	if keys := adminSigningKeys(t, f); len(keys) != 1 {
		t.Errorf("signing keys = %d, want 1 (no rotation from a rejected request)", len(keys))
	}
}

func TestAdminSigningKeys_CSRFRequired(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	sessionToken := createSession(t, f, adminUser.ID)
	router := buildAdminRouterWithCSRF(f)

	before := adminSigningKeys(t, f)
	rec := adminRequest(t, router, http.MethodPost, "/admin/signing-keys/rotate",
		sessionToken, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without a CSRF token status = %d, want 403", rec.Code)
	}

	after := adminSigningKeys(t, f)
	if len(after) != len(before) {
		t.Fatalf("a rejected POST rotated a key: %d keys before, %d after", len(before), len(after))
	}
}

func TestAdminSigningKeys_Rotate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	sessionToken := createSession(t, f, adminUser.ID)
	router := buildAdminRouterWithCSRF(f)

	before := adminSigningKeys(t, f)
	if len(before) != 1 {
		t.Fatalf("initial signing keys = %d, want 1", len(before))
	}
	firstKID := before[0].KID

	// The page shows the only key, marked current, with no retire button.
	rec := adminRequest(t, router, http.MethodGet, "/admin/signing-keys", sessionToken, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, firstKID) {
		t.Error("page does not list the current kid")
	}
	if !strings.Contains(body, "Current") {
		t.Error("page does not mark the signing key as current")
	}
	if !strings.Contains(body, "Only active key") {
		t.Error("page offers to retire the only active key")
	}
	if strings.Contains(body, "BEGIN RSA PRIVATE KEY") {
		t.Error("page rendered private key material")
	}

	res := postSigningKeyAction(t, f, router, sessionToken, "/admin/signing-keys/rotate")
	if res.Code != http.StatusFound {
		t.Fatalf("rotate status = %d, want 302; body: %s", res.Code, rec.Body.String())
	}
	if loc := res.Header().Get("Location"); loc != "/admin/signing-keys?flash=key-rotated" {
		t.Errorf("rotate redirect = %q, want the key-rotated flash", loc)
	}

	after := adminSigningKeys(t, f)
	if len(after) != 2 {
		t.Fatalf("signing keys after rotate = %d, want 2", len(after))
	}
	newKID := after[0].KID
	if newKID == firstKID {
		t.Fatal("rotation did not create a new key")
	}

	// The audit entry names the new kid and contains no key material.
	var audited bool
	for _, e := range f.audit.events {
		if e.Action == admin.AuditActionOAuthKeyRotate && e.TargetID == newKID {
			audited = true
			if strings.Contains(e.Detail, "PRIVATE KEY") || strings.Contains(e.TargetName, "PRIVATE KEY") {
				t.Error("audit entry contains private key material")
			}
		}
	}
	if !audited {
		t.Error("no oauth.key_rotate audit entry")
	}

	// The page now shows both keys as active with retire actions.
	rec = adminRequest(t, router, http.MethodGet, "/admin/signing-keys", sessionToken, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after rotate status = %d, want 200", rec.Code)
	}
	body = rec.Body.String()
	if !strings.Contains(body, firstKID) || !strings.Contains(body, newKID) {
		t.Error("page does not list both keys after rotation")
	}
	if strings.Count(body, `data-confirm="Retire this key?`) != 2 {
		t.Errorf("retire buttons = %d, want 2 (both keys are active)", strings.Count(body, `data-confirm="Retire this key?`))
	}
	if !strings.Contains(body, "Current") || !strings.Contains(body, ">Active<") {
		t.Error("page does not distinguish current from active keys")
	}
}

func TestAdminSigningKeys_RetireAndDelete(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	sessionToken := createSession(t, f, adminUser.ID)
	router := buildAdminRouterWithCSRF(f)

	firstKID := adminSigningKeys(t, f)[0].KID
	res := postSigningKeyAction(t, f, router, sessionToken, "/admin/signing-keys/rotate")
	if res.Code != http.StatusFound {
		t.Fatalf("rotate status = %d, want 302", res.Code)
	}
	newKID := adminSigningKeys(t, f)[0].KID

	// ── Retire the previous key. ─────────────────────────────────────────
	res = postSigningKeyAction(t, f, router, sessionToken, "/admin/signing-keys/"+firstKID+"/retire")
	if res.Code != http.StatusFound {
		t.Fatalf("retire status = %d, want 302", res.Code)
	}
	if loc := res.Header().Get("Location"); loc != "/admin/signing-keys?flash=key-retired" {
		t.Errorf("retire redirect = %q, want the key-retired flash", loc)
	}

	keys := adminSigningKeys(t, f)
	if len(keys) != 2 {
		t.Fatalf("signing keys after retire = %d, want 2 (history is kept)", len(keys))
	}
	var retired *oauth.SigningKey
	for _, key := range keys {
		if key.KID == firstKID {
			retired = key
		}
	}
	if retired == nil || !retired.Retired() {
		t.Fatal("the retired key is not marked retired in the store")
	}

	var retireAudited bool
	for _, e := range f.audit.events {
		if e.Action == admin.AuditActionOAuthKeyRetire && e.TargetID == firstKID {
			retireAudited = true
		}
	}
	if !retireAudited {
		t.Error("no oauth.key_retire audit entry")
	}

	// The page shows the retired state and a delete action.
	rec := adminRequest(t, router, http.MethodGet, "/admin/signing-keys", sessionToken, f.cfg.Session.CookieName, nil, "")
	body := rec.Body.String()
	if !strings.Contains(body, "Retired") {
		t.Error("page does not mark the key retired")
	}
	if !strings.Contains(body, `data-confirm="Delete this retired key?`) {
		t.Error("page does not offer to delete a retired key")
	}
	// Only one active key remains, so its retire button is withheld.
	if !strings.Contains(body, "Only active key") {
		t.Error("page offers to retire the only active key")
	}

	// ── The last active key cannot be retired through the UI either. ─────
	res = postSigningKeyAction(t, f, router, sessionToken, "/admin/signing-keys/"+newKID+"/retire")
	if res.Code != http.StatusOK {
		t.Fatalf("retire-last status = %d, want 200 with an error flash", res.Code)
	}
	if !strings.Contains(res.Body.String(), "This is the only active signing key") {
		t.Error("retiring the last active key did not render the refusal message")
	}

	// ── An active key cannot be deleted. ────────────────────────────────
	res = postSigningKeyAction(t, f, router, sessionToken, "/admin/signing-keys/"+newKID+"/delete")
	if res.Code != http.StatusOK {
		t.Fatalf("delete-active status = %d, want 200 with an error flash", res.Code)
	}
	if !strings.Contains(res.Body.String(), "Only a retired key can be deleted") {
		t.Error("deleting an active key did not render the refusal message")
	}

	// ── Delete the retired key for good. ────────────────────────────────
	res = postSigningKeyAction(t, f, router, sessionToken, "/admin/signing-keys/"+firstKID+"/delete")
	if res.Code != http.StatusFound {
		t.Fatalf("delete status = %d, want 302", res.Code)
	}
	if loc := res.Header().Get("Location"); loc != "/admin/signing-keys?flash=key-deleted" {
		t.Errorf("delete redirect = %q, want the key-deleted flash", loc)
	}

	keys = adminSigningKeys(t, f)
	if len(keys) != 1 || keys[0].KID != newKID {
		t.Fatalf("keys after delete = %d, want only the current key", len(keys))
	}

	var deleteAudited bool
	for _, e := range f.audit.events {
		if e.Action == admin.AuditActionOAuthKeyDelete && e.TargetID == firstKID {
			deleteAudited = true
		}
	}
	if !deleteAudited {
		t.Error("no oauth.key_delete audit entry")
	}

	// ── An unknown kid redirects with the error flash. ──────────────────
	res = postSigningKeyAction(t, f, router, sessionToken, "/admin/signing-keys/does-not-exist/retire")
	if res.Code != http.StatusFound {
		t.Fatalf("retire-unknown status = %d, want 302", res.Code)
	}
	if loc := res.Header().Get("Location"); loc != "/admin/signing-keys?flash=error" {
		t.Errorf("retire-unknown redirect = %q, want the error flash", loc)
	}
}
