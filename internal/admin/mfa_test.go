package admin_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/mfa"
)

// adminTestCode derives a current TOTP code for secret. It is an independent
// RFC 4226 implementation; the fixture's MFA service uses the wall clock.
func adminTestCode(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().UTC().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// enableMFAFor completes a TOTP enrollment for the given user through the MFA
// service, using a fixed clock so the code is deterministic.
func enableMFAFor(t *testing.T, f *fixture, userID, account string) {
	t.Helper()
	ctx := context.Background()
	enr, err := f.mfaSvc.BeginEnrollment(ctx, userID, account)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	codes, err := f.mfaSvc.ConfirmEnrollment(ctx, userID, adminTestCode(t, enr.Secret))
	if err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	if len(codes) != mfa.RecoveryCodeCount {
		t.Fatalf("got %d recovery codes; want %d", len(codes), mfa.RecoveryCodeCount)
	}
}

func TestAdminUsers_ShowsMFABadgeAndResetAction(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)

	enrolled, err := f.userSvc.Register(context.Background(), "enrolled", "enrolled@example.com", "password123")
	if err != nil {
		t.Fatalf("register enrolled: %v", err)
	}
	plain, err := f.userSvc.Register(context.Background(), "plain", "plain@example.com", "password123")
	if err != nil {
		t.Fatalf("register plain: %v", err)
	}
	enableMFAFor(t, f, enrolled.ID, "enrolled")

	router := buildAdminRouter(f)
	rec := adminRequest(t, router, http.MethodGet, "/admin/users", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/users status = %d; want 200", rec.Code)
	}
	body := rec.Body.String()

	if got := strings.Count(body, ">MFA</span>"); got != 1 {
		t.Errorf("MFA badge rendered %d times; want 1", got)
	}
	if !strings.Contains(body, "/admin/users/"+enrolled.ID+"/reset-mfa") {
		t.Error("enrolled user has no Reset MFA action")
	}
	if strings.Contains(body, "/admin/users/"+plain.ID+"/reset-mfa") {
		t.Error("a user without MFA has a Reset MFA action")
	}
}

func TestAdminUsers_ResetMFA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("deletes both tables and audits", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		adminUser := createAdminUser(t, f, "admin", "admin@example.com")
		token := createSession(t, f, adminUser.ID)
		target, err := f.userSvc.Register(ctx, "target", "target@example.com", "password123")
		if err != nil {
			t.Fatalf("register target: %v", err)
		}
		enableMFAFor(t, f, target.ID, "target")

		router := buildAdminRouterWithCSRF(f)
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/"+target.ID+"/reset-mfa",
			token, f.cfg.Session.CookieName, strings.NewReader(url.Values{}.Encode()), "application/x-www-form-urlencoded")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST without CSRF token status = %d; want 403", rec.Code)
		}
		if st, _ := f.mfaSvc.Status(ctx, target.ID); !st.Enabled {
			t.Fatal("a CSRF-less request reset MFA")
		}

		csrfToken, err := csrf.GenerateToken(token)
		if err != nil {
			t.Fatalf("generate csrf token: %v", err)
		}
		rec = adminRequest(t, router, http.MethodPost, "/admin/users/"+target.ID+"/reset-mfa",
			token, f.cfg.Session.CookieName,
			strings.NewReader(url.Values{"_csrf": {csrfToken}}.Encode()),
			"application/x-www-form-urlencoded")
		if rec.Code != http.StatusFound {
			t.Fatalf("POST status = %d; want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/admin/users?flash=mfa-reset" {
			t.Errorf("Location = %q; want /admin/users?flash=mfa-reset", loc)
		}

		if st, err := f.mfaSvc.Status(ctx, target.ID); err != nil || st.Enabled {
			t.Fatalf("status after reset = %+v, %v; want disabled", st, err)
		}

		var n int
		if err := f.db.QueryRow(`SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = ?`, target.ID).Scan(&n); err != nil {
			t.Fatalf("count recovery codes: %v", err)
		}
		if n != 0 {
			t.Errorf("recovery codes survived the reset: %d", n)
		}

		var audited bool
		for _, e := range f.audit.events {
			if e.Action == admin.AuditActionUserMFAReset && e.TargetID == target.ID {
				audited = true
			}
		}
		if !audited {
			t.Errorf("no %s audit event for %s", admin.AuditActionUserMFAReset, target.ID)
		}

		// The security log also records it, so "who reset my MFA" is visible
		// next to every other sign-in event.
		events, err := f.authStore.List(ctx, authlog.Filter{})
		if err != nil {
			t.Fatalf("list auth events: %v", err)
		}
		var logged bool
		for _, e := range events {
			if e.Event == authlog.EventMFAReset && e.UserID == target.ID {
				logged = true
			}
		}
		if !logged {
			t.Errorf("no %s authentication event for %s", authlog.EventMFAReset, target.ID)
		}
	})

	t.Run("requires an admin session", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		target, err := f.userSvc.Register(ctx, "target", "target@example.com", "password123")
		if err != nil {
			t.Fatalf("register target: %v", err)
		}
		enableMFAFor(t, f, target.ID, "target")

		// No session at all.
		router := buildAdminRouterWithCSRF(f)
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/"+target.ID+"/reset-mfa", "", f.cfg.Session.CookieName, nil, "")
		if rec.Code != http.StatusFound {
			t.Fatalf("unauthenticated status = %d; want 302 to /login", rec.Code)
		}
		if st, _ := f.mfaSvc.Status(ctx, target.ID); !st.Enabled {
			t.Fatal("an unauthenticated request reset MFA")
		}

		// A non-admin session is refused too.
		nonAdmin, err := f.userSvc.Register(ctx, "nonadmin", "nonadmin@example.com", "password123")
		if err != nil {
			t.Fatalf("register non-admin: %v", err)
		}
		token := createSession(t, f, nonAdmin.ID)
		rec = adminRequest(t, router, http.MethodPost, "/admin/users/"+target.ID+"/reset-mfa", token, f.cfg.Session.CookieName, nil, "")
		if rec.Code != http.StatusFound {
			t.Fatalf("non-admin status = %d; want 302 to /login", rec.Code)
		}
		if st, _ := f.mfaSvc.Status(ctx, target.ID); !st.Enabled {
			t.Fatal("a non-admin request reset MFA")
		}
	})
}

func TestAdminSettings_RequireMFA(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	rec := adminRequest(t, router, http.MethodGet, "/admin/settings", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/settings status = %d; want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="auth_require_mfa"`) {
		t.Fatal("settings page has no require-MFA checkbox")
	}

	form := url.Values{}
	form.Set("auth_password_enabled", "on")
	form.Set("auth_passkey_enabled", "on")
	form.Set("auth_require_mfa", "on")
	rec = adminRequest(t, router, http.MethodPost, "/admin/settings/auth-methods", token,
		f.cfg.Session.CookieName, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if rec.Code != http.StatusFound {
		t.Fatalf("POST status = %d; want 302", rec.Code)
	}

	got, err := f.settings.Get(context.Background(), "auth_require_mfa")
	if err != nil {
		t.Fatalf("get auth_require_mfa: %v", err)
	}
	if got != "true" {
		t.Errorf("auth_require_mfa = %q; want true", got)
	}

	// Saving the form again without the checkbox turns it back off.
	form.Del("auth_require_mfa")
	rec = adminRequest(t, router, http.MethodPost, "/admin/settings/auth-methods", token,
		f.cfg.Session.CookieName, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if rec.Code != http.StatusFound {
		t.Fatalf("POST status = %d; want 302", rec.Code)
	}
	if got, _ := f.settings.Get(context.Background(), "auth_require_mfa"); got != "false" {
		t.Errorf("auth_require_mfa = %q; want false", got)
	}
}
