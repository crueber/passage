package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/user"
)

// enableSMTP makes the fixture's config able to send mail. Handlers read the
// config snapshot directly, so a test can turn this on without rebuilding.
func enableSMTP(f *fixture) {
	f.cfg.SMTP.Host = "smtp.example.com"
	f.cfg.SMTP.From = "passage@example.com"
}

// TestGetInviteUser_RendersForm proves the invitation page renders even with no
// mail configured, and explains what is missing.
func TestGetInviteUser_RendersForm(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	adminUser := createAdminUser(t, f, "inviteadmin", "inviteadmin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	rec := adminRequest(t, router, http.MethodGet, "/admin/users/invite", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Invite user", `name="email"`, `name="expiry_days"`, "No pending invitations", "SMTP server"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

// TestPostInviteUser_CreatesPendingInvite proves the admin flow stores an
// invitation and emails the link without creating a user.
func TestPostInviteUser_CreatesPendingInvite(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	enableSMTP(f)
	adminUser := createAdminUser(t, f, "invitesender", "invitesender@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	form := url.Values{
		"email":       {"friend@example.com"},
		"name":        {"Friend Person"},
		"expiry_days": {"3"},
	}
	rec := adminRequest(t, router, http.MethodPost, "/admin/users/invite", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body:\n%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/users/invite?flash=invited" {
		t.Errorf("Location = %q, want the invite page with a success flash", loc)
	}

	sent := f.mailer.sentInvites()
	if len(sent) != 1 {
		t.Fatalf("sent invitations = %d, want 1", len(sent))
	}
	if sent[0].To != "friend@example.com" || sent[0].Name != "Friend Person" {
		t.Errorf("invitation = %+v, want the submitted address and name", sent[0])
	}
	if sent[0].Inviter != "invitesender" {
		t.Errorf("inviter = %q, want the acting admin's username", sent[0].Inviter)
	}
	if !strings.Contains(sent[0].URL, "/invite/") {
		t.Errorf("invite URL = %q, want a /invite/<token> link", sent[0].URL)
	}

	// The whole point: no account yet.
	if _, err := f.userStore.GetByEmail(context.Background(), "friend@example.com"); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("invitation created a user: %v", err)
	}

	// The pending list shows the invitation after the redirect target loads.
	rec = adminRequest(t, router, http.MethodGet, "/admin/users/invite", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET invite page status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "friend@example.com") {
		t.Error("pending invitation is not listed on the invite page")
	}

	if len(f.audit.events) == 0 || f.audit.events[len(f.audit.events)-1].Action != "user.invite" {
		t.Errorf("audit events = %+v, want a user.invite entry", f.audit.events)
	}
}

// TestPostInviteUser_Rejections covers the conditions that must render an
// error instead of storing anything.
func TestPostInviteUser_Rejections(t *testing.T) {
	t.Parallel()

	t.Run("existing email", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		enableSMTP(f)
		adminUser := createAdminUser(t, f, "existingadmin", "existingadmin@example.com")
		if _, err := f.userSvc.Register(context.Background(), "already", "already@example.com", "password123"); err != nil {
			t.Fatalf("Register: %v", err)
		}
		token := createSession(t, f, adminUser.ID)
		router := buildAdminRouter(f)

		form := url.Values{"email": {"already@example.com"}, "expiry_days": {"7"}}
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/invite", token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (re-rendered form)", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "An account with that email already exists.") {
			t.Error("error message about the existing account is missing")
		}
		if len(f.mailer.sentInvites()) != 0 {
			t.Error("an invitation email was sent for an existing account")
		}
	})

	t.Run("no SMTP", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		adminUser := createAdminUser(t, f, "nosmtpadmin", "nosmtpadmin@example.com")
		token := createSession(t, f, adminUser.ID)
		router := buildAdminRouter(f)

		form := url.Values{"email": {"someone@example.com"}, "expiry_days": {"7"}}
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/invite", token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (re-rendered form)", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "SMTP must be configured") {
			t.Error("error message about SMTP is missing")
		}
	})

	t.Run("bad expiry", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		enableSMTP(f)
		adminUser := createAdminUser(t, f, "expiryadmin", "expiryadmin@example.com")
		token := createSession(t, f, adminUser.ID)
		router := buildAdminRouter(f)

		form := url.Values{"email": {"someone@example.com"}, "expiry_days": {"365"}}
		rec := adminRequest(t, router, http.MethodPost, "/admin/users/invite", token, f.cfg.Session.CookieName,
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (re-rendered form)", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "between 1 and 30") {
			t.Error("error message about the expiry range is missing")
		}
	})
}

// TestPostInviteUser_SendFailureLeavesNothingBehind proves a failed email does
// not leave an invitation nobody received.
func TestPostInviteUser_SendFailureLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	enableSMTP(f)
	f.mailer.err = errors.New("smtp down")
	adminUser := createAdminUser(t, f, "failadmin", "failadmin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	form := url.Values{"email": {"unreachable@example.com"}, "expiry_days": {"7"}}
	rec := adminRequest(t, router, http.MethodPost, "/admin/users/invite", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (re-rendered form)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Could not send the invitation email.") {
		t.Error("error message about the failed send is missing")
	}

	pending, err := f.userSvc.ListPendingInvitations(context.Background())
	if err != nil {
		t.Fatalf("ListPendingInvitations: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending invitations after failed send = %d, want 0", len(pending))
	}
}

// TestPostRevokeInvitation proves revoking removes the pending row so its link
// stops working.
func TestPostRevokeInvitation(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	enableSMTP(f)
	adminUser := createAdminUser(t, f, "revokeadmin", "revokeadmin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)
	ctx := context.Background()

	inv, err := f.userSvc.CreateInvitation(ctx, "revokee@example.com", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	rec := adminRequest(t, router, http.MethodPost, "/admin/users/invitations/"+inv.ID+"/revoke", token, f.cfg.Session.CookieName, nil, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/users/invite?flash=invite-revoked" {
		t.Errorf("Location = %q, want the invite page with a revocation flash", loc)
	}

	if _, err := f.userSvc.GetPendingInvitation(ctx, inv.Token); !errors.Is(err, user.ErrInvitationNotFound) {
		t.Errorf("revoked invitation: got %v, want ErrInvitationNotFound", err)
	}
}
