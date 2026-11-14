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

// profileRequest builds a POST to /profile carrying the given signed-in user.
func profileRequest(t *testing.T, form url.Values, u *user.User) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if u != nil {
		req = req.WithContext(session.WithUser(req.Context(), u))
	}
	return req
}

// TestHandler_GetProfile renders the profile page with the current display
// name and the save button below the field.
func TestHandler_GetProfile(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)
	ctx := context.Background()

	u, err := f.userSvc.Register(ctx, "profilepage", "profilepage@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := f.userSvc.UpdateDisplayName(ctx, u.ID, "Chris Rueber"); err != nil {
		t.Fatalf("UpdateDisplayName: %v", err)
	}
	u, err = f.userStore.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/profile?flash=saved", nil)
	req = req.WithContext(session.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	f.handler.GetProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<title>Profile — Passage</title>",
		`action="/profile"`,
		`name="display_name"`,
		`value="Chris Rueber"`,
		"Save changes",
		"profilepage",
		"profilepage@example.com",
		"Profile updated.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("profile page missing %q", want)
		}
	}
}

// TestHandler_PostUpdateProfile_Theme covers the account-level theme override:
// it is validated, stored, and rendered server-side on the next page load.
func TestHandler_PostUpdateProfile_Theme(t *testing.T) {
	t.Parallel()

	t.Run("saves and renders a theme", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "themed", "themed@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		rec := httptest.NewRecorder()
		f.handler.PostUpdateProfile(rec, profileRequest(t, url.Values{
			"display_name": {"Themed User"},
			"theme":        {"arctic-blue"},
		}, u))

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		fresh, err := f.userStore.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if fresh.Theme != "arctic-blue" {
			t.Errorf("theme = %q, want arctic-blue", fresh.Theme)
		}

		req := httptest.NewRequest(http.MethodGet, "/profile", nil)
		req = req.WithContext(session.WithUser(req.Context(), fresh))
		rec = httptest.NewRecorder()
		f.handler.GetProfile(rec, req)
		body := rec.Body.String()
		for _, want := range []string{`data-theme="arctic-blue"`, `<option value="arctic-blue" selected>Arctic Blue</option>`} {
			if !strings.Contains(body, want) {
				t.Errorf("profile page missing %q", want)
			}
		}
	})

	t.Run("unknown theme is refused", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "badtheme", "badtheme@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if err := f.userSvc.UpdateTheme(ctx, u.ID, "arctic-blue"); err != nil {
			t.Fatalf("UpdateTheme: %v", err)
		}

		rec := httptest.NewRecorder()
		f.handler.PostUpdateProfile(rec, profileRequest(t, url.Values{
			"display_name": {"Bad Theme"},
			"theme":        {"not-a-theme"},
		}, u))

		if loc := rec.Header().Get("Location"); loc != "/profile?flash=invalid" {
			t.Errorf("Location = %q, want the invalid flash", loc)
		}
		fresh, err := f.userStore.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if fresh.Theme != "arctic-blue" {
			t.Errorf("theme = %q, want the previous value", fresh.Theme)
		}
	})
}

// TestHandler_PostUpdateProfile covers the self-service display-name edit that
// the profile page exposes.
func TestHandler_PostUpdateProfile(t *testing.T) {
	t.Parallel()

	t.Run("saves a trimmed name", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "profileuser", "profileuser@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		rec := httptest.NewRecorder()
		f.handler.PostUpdateProfile(rec, profileRequest(t, url.Values{"display_name": {"  Sam Rivera  "}}, u))

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/profile?flash=saved" {
			t.Errorf("Location = %q, want the profile page with a success flash", loc)
		}

		fresh, err := f.userStore.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if fresh.Name != "Sam Rivera" {
			t.Errorf("display name = %q, want the trimmed value", fresh.Name)
		}
		// The edit writes only the name: credentials stay intact.
		if fresh.PasswordHash != u.PasswordHash {
			t.Error("profile update changed password_hash")
		}
	})

	t.Run("clearing the name is allowed", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "clearuser", "clearuser@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if err := f.userSvc.UpdateDisplayName(ctx, u.ID, "Old Name"); err != nil {
			t.Fatalf("UpdateDisplayName: %v", err)
		}

		rec := httptest.NewRecorder()
		f.handler.PostUpdateProfile(rec, profileRequest(t, url.Values{"display_name": {""}}, u))

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		fresh, err := f.userStore.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if fresh.Name != "" {
			t.Errorf("display name = %q, want empty", fresh.Name)
		}
	})

	t.Run("over-long name is refused", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)
		ctx := context.Background()

		u, err := f.userSvc.Register(ctx, "longname", "longname@example.com", "password123")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if err := f.userSvc.UpdateDisplayName(ctx, u.ID, "Keep Me"); err != nil {
			t.Fatalf("UpdateDisplayName: %v", err)
		}

		rec := httptest.NewRecorder()
		f.handler.PostUpdateProfile(rec, profileRequest(t, url.Values{
			"display_name": {strings.Repeat("x", user.MaxDisplayNameLength+1)},
		}, u))

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/profile?flash=invalid" {
			t.Errorf("Location = %q, want the invalid-name flash", loc)
		}
		fresh, err := f.userStore.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if fresh.Name != "Keep Me" {
			t.Errorf("display name = %q, want the previous value unchanged", fresh.Name)
		}
	})

	t.Run("signed-out request is sent to sign in", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixture(t, true)

		rec := httptest.NewRecorder()
		f.handler.PostUpdateProfile(rec, profileRequest(t, url.Values{"display_name": {"Nobody"}}, nil))

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("Location = %q, want /login", loc)
		}
	})
}
