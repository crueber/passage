package user_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// passwordRequest builds a POST to /password carrying the given signed-in user.
func passwordRequest(t *testing.T, form url.Values, u *user.User) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if u != nil {
		req = req.WithContext(session.WithUser(req.Context(), u))
	}
	return req
}

// TestHandler_PostChangePassword covers the self-service password change on the
// Security page: current-password verification, validation, session rotation,
// and the disabled-policy gate.
func TestHandler_PostChangePassword(t *testing.T) {
	t.Parallel()

	t.Run("changes the password and keeps this browser signed in", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "changepw", "changepw@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		// A second session stands in for another device.
		if _, _, err := f.sessionSvc.CreateSession(ctx, u.ID, nil, "10.0.0.2", "other"); err != nil {
			t.Fatalf("CreateSession other: %v", err)
		}

		form := url.Values{
			"current_password": {"password123"},
			"new_password":     {"newpassword456"},
			"confirm_password": {"newpassword456"},
		}
		rec := httptest.NewRecorder()
		f.handler.PostChangePassword(rec, passwordRequest(t, form, u))

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302; body:\n%s", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "/passkeys?tab=password&flash=password-changed" {
			t.Errorf("Location = %q, want the Password tab with a success flash", loc)
		}

		var replacement string
		for _, c := range rec.Result().Cookies() {
			if c.Name == f.cfg.Session.CookieName && c.Value != "" {
				replacement = c.Value
			}
		}
		if replacement == "" {
			t.Fatal("replacement session cookie was not set")
		}

		if _, err := f.userSvc.Authenticate(ctx, "changepw", "newpassword456"); err != nil {
			t.Errorf("Authenticate with the new password: %v", err)
		}
		if _, err := f.userSvc.Authenticate(ctx, "changepw", "password123"); err == nil {
			t.Error("the old password still works")
		}

		sessions, err := f.sessionSvc.ListAll(ctx)
		if err != nil {
			t.Fatalf("ListAll: %v", err)
		}
		var forUser []string
		for _, s := range sessions {
			if s.UserID == u.ID {
				forUser = append(forUser, s.ID)
			}
		}
		if len(forUser) != 1 {
			t.Fatalf("sessions for user = %d, want only the replacement", len(forUser))
		}
		if forUser[0] != replacement {
			t.Errorf("remaining session is not the cookie issued to this browser")
		}
	})

	t.Run("wrong current password changes nothing", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "wrongpw", "wrongpw@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		form := url.Values{
			"current_password": {"not-the-password"},
			"new_password":     {"newpassword456"},
			"confirm_password": {"newpassword456"},
		}
		rec := httptest.NewRecorder()
		f.handler.PostChangePassword(rec, passwordRequest(t, form, u))

		if loc := rec.Header().Get("Location"); loc != "/passkeys?tab=password&flash=password-invalid" {
			t.Errorf("Location = %q, want the invalid-current-password flash", loc)
		}
		if _, err := f.userSvc.Authenticate(ctx, "wrongpw", "password123"); err != nil {
			t.Errorf("old password no longer works: %v", err)
		}
	})

	t.Run("new password too short", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "shortpw", "shortpw@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		form := url.Values{
			"current_password": {"password123"},
			"new_password":     {"short"},
			"confirm_password": {"short"},
		}
		rec := httptest.NewRecorder()
		f.handler.PostChangePassword(rec, passwordRequest(t, form, u))

		if loc := rec.Header().Get("Location"); loc != "/passkeys?tab=password&flash=password-too-short" {
			t.Errorf("Location = %q, want the too-short flash", loc)
		}
	})

	t.Run("confirmation mismatch", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "mismatchpw", "mismatchpw@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		form := url.Values{
			"current_password": {"password123"},
			"new_password":     {"newpassword456"},
			"confirm_password": {"newpassword789"},
		}
		rec := httptest.NewRecorder()
		f.handler.PostChangePassword(rec, passwordRequest(t, form, u))

		if loc := rec.Header().Get("Location"); loc != "/passkeys?tab=password&flash=password-mismatch" {
			t.Errorf("Location = %q, want the mismatch flash", loc)
		}
	})

	t.Run("account without a password can set one", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.CreateExternalUser(ctx, "linked", "linked@example.com", "Linked User", true)
		if err != nil {
			t.Fatalf("CreateExternalUser: %v", err)
		}

		form := url.Values{
			"new_password":     {"newpassword456"},
			"confirm_password": {"newpassword456"},
		}
		rec := httptest.NewRecorder()
		f.handler.PostChangePassword(rec, passwordRequest(t, form, u))

		if loc := rec.Header().Get("Location"); loc != "/passkeys?tab=password&flash=password-changed" {
			t.Errorf("Location = %q, want the success flash", loc)
		}
		if _, err := f.userSvc.Authenticate(ctx, "linked", "newpassword456"); err != nil {
			t.Errorf("Authenticate after setting a password: %v", err)
		}
	})

	t.Run("password sign-in disabled is refused", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()
		f.settings.values["auth_password_enabled"] = "false"

		u, err := f.userSvc.Register(ctx, "disabledpw", "disabledpw@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		form := url.Values{
			"current_password": {"password123"},
			"new_password":     {"newpassword456"},
			"confirm_password": {"newpassword456"},
		}
		rec := httptest.NewRecorder()
		f.handler.PostChangePassword(rec, passwordRequest(t, form, u))

		if loc := rec.Header().Get("Location"); loc != "/passkeys?flash=password-disabled" {
			t.Errorf("Location = %q, want the disabled flash", loc)
		}
		if _, err := f.userSvc.Authenticate(ctx, "disabledpw", "password123"); err != nil {
			t.Errorf("password changed while the policy was off: %v", err)
		}
	})

	t.Run("signed-out request is sent to sign in", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)

		rec := httptest.NewRecorder()
		f.handler.PostChangePassword(rec, passwordRequest(t, url.Values{}, nil))

		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("Location = %q, want /login", loc)
		}
	})
}
