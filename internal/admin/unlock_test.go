package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/ratelimit"
)

// buildAdminRouterWithCSRF mirrors the production admin route group, including
// the session-bound CSRF middleware that buildAdminRouter omits.
func buildAdminRouterWithCSRF(f *fixture) http.Handler {
	r := chi.NewRouter()
	r.Route("/admin", func(r chi.Router) {
		r.Use(admin.RequireAdmin(f.sessionSvc, f.cfg))
		r.Use(csrf.ProtectAuthenticated(f.cfg.Session.CookieName))
		f.handler.Routes(r)
	})
	return r
}

func TestAdminUsers_ShowsLockNoticeOnlyForLocked(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	locked, err := f.userSvc.Register(context.Background(), "lockeduser", "locked@example.com", "password123")
	if err != nil {
		t.Fatalf("register locked user: %v", err)
	}
	other, err := f.userSvc.Register(context.Background(), "otheruser", "other@example.com", "password123")
	if err != nil {
		t.Fatalf("register other user: %v", err)
	}

	if err := f.throttleStore.Lock(context.Background(), locked.Username, time.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("lock user: %v", err)
	}

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodGet, "/admin/users", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/users status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, ">Locked</span>") {
		t.Error("user list does not render a Locked badge")
	}
	if got := strings.Count(body, ">Locked</span>"); got != 1 {
		t.Errorf("Locked badge rendered %d times, want 1 (only the locked user)", got)
	}
	if !strings.Contains(body, "/admin/users/"+locked.ID+"/unlock") {
		t.Errorf("locked user %s has no Unlock action", locked.ID)
	}
	if strings.Contains(body, "/admin/users/"+other.ID+"/unlock") {
		t.Errorf("unlocked user %s has an Unlock action", other.ID)
	}

	// Existing row actions must remain intact.
	for _, action := range []string{"/reset-password", "/delete"} {
		if !strings.Contains(body, "/admin/users/"+locked.ID+action) {
			t.Errorf("locked user row is missing the %s action", action)
		}
	}
}

func TestAdminUsers_Unlock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("clears the lock and writes an audit entry", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		adminUser := createAdminUser(t, f, "admin", "admin@example.com")
		token := createSession(t, f, adminUser.ID)
		target, err := f.userSvc.Register(ctx, "target", "target@example.com", "password123")
		if err != nil {
			t.Fatalf("register target: %v", err)
		}
		if err := f.throttleStore.Lock(ctx, target.Username, time.Now().Add(15*time.Minute)); err != nil {
			t.Fatalf("lock target: %v", err)
		}

		csrfToken, err := csrf.GenerateToken(token)
		if err != nil {
			t.Fatalf("generate csrf token: %v", err)
		}
		form := url.Values{"_csrf": {csrfToken}}

		router := buildAdminRouterWithCSRF(f)
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/"+target.ID+"/unlock",
			token, f.cfg.Session.CookieName, strings.NewReader(form.Encode()),
			"application/x-www-form-urlencoded")

		if rec.Code != http.StatusFound {
			t.Fatalf("unlock status = %d, want 302; body:\n%s", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "/admin/users?flash=unlocked" {
			t.Errorf("unlock redirect = %q, want %q", loc, "/admin/users?flash=unlocked")
		}
		if _, err := f.throttleStore.Get(ctx, target.Username); !errors.Is(err, ratelimit.ErrNotFound) {
			t.Errorf("throttle row after unlock = %v, want ErrNotFound", err)
		}

		var found bool
		for _, e := range f.audit.events {
			if e.Action == admin.AuditActionUserUnlock && e.TargetID == target.ID {
				found = true
				if e.TargetName != target.Username {
					t.Errorf("audit TargetName = %q, want %q", e.TargetName, target.Username)
				}
			}
		}
		if !found {
			t.Errorf("no %s audit entry recorded: %+v", admin.AuditActionUserUnlock, f.audit.events)
		}
	})

	t.Run("rejects a request without a CSRF token", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		adminUser := createAdminUser(t, f, "admin", "admin@example.com")
		token := createSession(t, f, adminUser.ID)
		target, err := f.userSvc.Register(ctx, "target", "target@example.com", "password123")
		if err != nil {
			t.Fatalf("register target: %v", err)
		}
		if err := f.throttleStore.Lock(ctx, target.Username, time.Now().Add(15*time.Minute)); err != nil {
			t.Fatalf("lock target: %v", err)
		}

		router := buildAdminRouterWithCSRF(f)
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/"+target.ID+"/unlock",
			token, f.cfg.Session.CookieName, nil, "")

		if rec.Code != http.StatusForbidden {
			t.Fatalf("unlock without CSRF status = %d, want 403", rec.Code)
		}
		if _, err := f.throttleStore.Get(ctx, target.Username); err != nil {
			t.Errorf("lock was cleared without a CSRF token: %v", err)
		}
		for _, e := range f.audit.events {
			if e.Action == admin.AuditActionUserUnlock {
				t.Errorf("audit entry written for a rejected unlock: %+v", e)
			}
		}
	})

	t.Run("requires an admin session", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		nonAdmin, err := f.userSvc.Register(ctx, "user", "user@example.com", "password123")
		if err != nil {
			t.Fatalf("register non-admin: %v", err)
		}
		token := createSession(t, f, nonAdmin.ID)
		target, err := f.userSvc.Register(ctx, "target", "target@example.com", "password123")
		if err != nil {
			t.Fatalf("register target: %v", err)
		}
		if err := f.throttleStore.Lock(ctx, target.Username, time.Now().Add(15*time.Minute)); err != nil {
			t.Fatalf("lock target: %v", err)
		}

		csrfToken, err := csrf.GenerateToken(token)
		if err != nil {
			t.Fatalf("generate csrf token: %v", err)
		}
		form := url.Values{"_csrf": {csrfToken}}

		router := buildAdminRouterWithCSRF(f)
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/"+target.ID+"/unlock",
			token, f.cfg.Session.CookieName, strings.NewReader(form.Encode()),
			"application/x-www-form-urlencoded")

		if rec.Code != http.StatusFound {
			t.Fatalf("non-admin unlock status = %d, want 302 redirect", rec.Code)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/login") {
			t.Errorf("non-admin unlock redirect = %q, want /login", loc)
		}
		if _, err := f.throttleStore.Get(ctx, target.Username); err != nil {
			t.Errorf("non-admin cleared a lock: %v", err)
		}
	})

	t.Run("unknown user redirects to the list", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		adminUser := createAdminUser(t, f, "admin", "admin@example.com")
		token := createSession(t, f, adminUser.ID)
		csrfToken, err := csrf.GenerateToken(token)
		if err != nil {
			t.Fatalf("generate csrf token: %v", err)
		}
		form := url.Values{"_csrf": {csrfToken}}

		router := buildAdminRouterWithCSRF(f)
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/no-such-user/unlock",
			token, f.cfg.Session.CookieName, strings.NewReader(form.Encode()),
			"application/x-www-form-urlencoded")

		if rec.Code != http.StatusFound {
			t.Fatalf("unknown user unlock status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/admin/users" {
			t.Errorf("unknown user redirect = %q, want /admin/users", loc)
		}
	})
}
