package user_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// TestInvitation_Lifecycle covers the promise of an invitation: no user exists
// while it is pending, accepting it creates exactly one verified account, and
// the link cannot be replayed.
func TestInvitation_Lifecycle(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	cfg := testConfig(false) // registration is off; invitations are the way in
	withSMTP(cfg)
	svc := user.NewService(store, store, nil, cfg)
	ctx := context.Background()

	inv, err := svc.CreateInvitation(ctx, "Invitee@Example.com", "Invitee Person", "admin", 7*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if len(inv.Token) != 64 {
		t.Errorf("token length = %d, want 64 hex chars (32 bytes)", len(inv.Token))
	}
	if inv.Email != "invitee@example.com" {
		t.Errorf("email = %q, want the normalised address", inv.Email)
	}

	// The invite must not create the account.
	if _, err := store.GetByEmail(ctx, "invitee@example.com"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("GetByEmail while pending: got %v, want ErrNotFound", err)
	}

	pending, err := svc.ListPendingInvitations(ctx)
	if err != nil {
		t.Fatalf("ListPendingInvitations: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != inv.ID {
		t.Fatalf("pending invitations = %+v, want the one just created", pending)
	}

	u, err := svc.AcceptInvitation(ctx, inv.Token, "invitee", "password123")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if u.Email != "invitee@example.com" || u.Name != "Invitee Person" {
		t.Errorf("accepted user = %+v, want the invitation's email and name", u)
	}
	if !u.IsActive || !u.EmailVerified {
		t.Errorf("accepted user active=%v verified=%v, want both true", u.IsActive, u.EmailVerified)
	}
	if _, err := svc.Authenticate(ctx, "invitee", "password123"); err != nil {
		t.Errorf("Authenticate after accepting: %v", err)
	}

	// The link is single-use.
	if _, err := svc.AcceptInvitation(ctx, inv.Token, "invitee2", "password123"); !errors.Is(err, user.ErrInvitationAccepted) {
		t.Errorf("second accept: got %v, want ErrInvitationAccepted", err)
	}

	pending, err = svc.ListPendingInvitations(ctx)
	if err != nil {
		t.Fatalf("ListPendingInvitations after accept: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending invitations after accept = %d, want 0", len(pending))
	}
}

// TestCreateInvitation_Refusals covers the two conditions that must stop an
// invitation before anything is stored.
func TestCreateInvitation_Refusals(t *testing.T) {
	t.Parallel()

	t.Run("SMTP is required", func(t *testing.T) {
		t.Parallel()
		db := testutil.NewTestDB(t)
		store := user.NewStore(db)
		cfg := testConfig(false) // no SMTP
		svc := user.NewService(store, store, nil, cfg)

		_, err := svc.CreateInvitation(context.Background(), "someone@example.com", "", "admin", time.Hour)
		if !errors.Is(err, user.ErrSMTPNotConfigured) {
			t.Errorf("got %v, want ErrSMTPNotConfigured", err)
		}
	})

	t.Run("existing account is refused", func(t *testing.T) {
		t.Parallel()
		db := testutil.NewTestDB(t)
		store := user.NewStore(db)
		cfg := testConfig(true)
		withSMTP(cfg)
		svc := user.NewService(store, store, nil, cfg)
		ctx := context.Background()

		if _, err := svc.Register(ctx, "already", "already@example.com", "password123"); err != nil {
			t.Fatalf("Register: %v", err)
		}

		_, err := svc.CreateInvitation(ctx, "already@example.com", "", "admin", time.Hour)
		if !errors.Is(err, user.ErrEmailTaken) {
			t.Errorf("got %v, want ErrEmailTaken", err)
		}
	})

	t.Run("invalid address is refused", func(t *testing.T) {
		t.Parallel()
		db := testutil.NewTestDB(t)
		store := user.NewStore(db)
		cfg := testConfig(false)
		withSMTP(cfg)
		svc := user.NewService(store, store, nil, cfg)

		_, err := svc.CreateInvitation(context.Background(), "not-an-address", "", "admin", time.Hour)
		if !errors.Is(err, user.ErrEmailRequired) {
			t.Errorf("got %v, want ErrEmailRequired", err)
		}
	})
}

// TestCreateInvitation_ReplacesPending proves a second invite for the same
// address invalidates the first link rather than leaving two live links.
func TestCreateInvitation_ReplacesPending(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	cfg := testConfig(false)
	withSMTP(cfg)
	svc := user.NewService(store, store, nil, cfg)
	ctx := context.Background()

	first, err := svc.CreateInvitation(ctx, "repeat@example.com", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("first CreateInvitation: %v", err)
	}
	second, err := svc.CreateInvitation(ctx, "repeat@example.com", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("second CreateInvitation: %v", err)
	}

	if _, err := svc.GetPendingInvitation(ctx, first.Token); !errors.Is(err, user.ErrInvitationNotFound) {
		t.Errorf("old token: got %v, want ErrInvitationNotFound", err)
	}
	if _, err := svc.GetPendingInvitation(ctx, second.Token); err != nil {
		t.Errorf("new token: %v", err)
	}
}

// TestAcceptInvitation_UsernameTakenKeepsLinkUsable proves a validation failure
// does not burn the invitation.
func TestAcceptInvitation_UsernameTakenKeepsLinkUsable(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	cfg := testConfig(true)
	withSMTP(cfg)
	svc := user.NewService(store, store, nil, cfg)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "taken", "taken@example.com", "password123"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	inv, err := svc.CreateInvitation(ctx, "fresh@example.com", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	if _, err := svc.AcceptInvitation(ctx, inv.Token, "taken", "password123"); !errors.Is(err, user.ErrUsernameTaken) {
		t.Fatalf("accept with taken username: got %v, want ErrUsernameTaken", err)
	}
	if _, err := svc.AcceptInvitation(ctx, inv.Token, "fresh", "password123"); err != nil {
		t.Fatalf("accept after retry: %v", err)
	}
}

// TestInvitation_ExpiryAndRevoke covers both ways a link stops working.
func TestInvitation_ExpiryAndRevoke(t *testing.T) {
	t.Parallel()

	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		db := testutil.NewTestDB(t)
		store := user.NewStore(db)
		cfg := testConfig(false)
		withSMTP(cfg)
		svc := user.NewService(store, store, nil, cfg)
		ctx := context.Background()

		inv, err := svc.CreateInvitation(ctx, "late@example.com", "", "admin", time.Hour)
		if err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE invitations SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute), inv.ID); err != nil {
			t.Fatalf("expire invitation: %v", err)
		}

		if _, err := svc.GetPendingInvitation(ctx, inv.Token); !errors.Is(err, user.ErrInvitationExpired) {
			t.Errorf("GetPendingInvitation: got %v, want ErrInvitationExpired", err)
		}
		if _, err := svc.AcceptInvitation(ctx, inv.Token, "late", "password123"); !errors.Is(err, user.ErrInvitationExpired) {
			t.Errorf("AcceptInvitation: got %v, want ErrInvitationExpired", err)
		}
		if _, err := store.GetByEmail(ctx, "late@example.com"); !errors.Is(err, user.ErrNotFound) {
			t.Errorf("expired invite created an account: %v", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		t.Parallel()
		db := testutil.NewTestDB(t)
		store := user.NewStore(db)
		cfg := testConfig(false)
		withSMTP(cfg)
		svc := user.NewService(store, store, nil, cfg)
		ctx := context.Background()

		inv, err := svc.CreateInvitation(ctx, "revoked@example.com", "", "admin", time.Hour)
		if err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		if err := svc.RevokeInvitation(ctx, inv.ID); err != nil {
			t.Fatalf("RevokeInvitation: %v", err)
		}
		if _, err := svc.GetPendingInvitation(ctx, inv.Token); !errors.Is(err, user.ErrInvitationNotFound) {
			t.Errorf("after revoke: got %v, want ErrInvitationNotFound", err)
		}
		if err := svc.RevokeInvitation(ctx, inv.ID); !errors.Is(err, user.ErrInvitationNotFound) {
			t.Errorf("second revoke: got %v, want ErrInvitationNotFound", err)
		}
	})
}

// ─── Handler ─────────────────────────────────────────────────────────────────

// newInviteHandlerFixture builds a full handler graph whose registration policy
// is off and whose invitations can actually be accepted.
func newInviteHandlerFixture(t *testing.T) (*handlerFixture, *recordingSender) {
	t.Helper()
	sender := &recordingSender{}
	f := newFullHandlerFixtureWith(t, false, withSMTP, sender)
	return f, sender
}

// TestHandler_GetInviteAccept proves a pending link renders the account form
// with the invited address, and that an unusable link is sent to sign-in with
// an explanation.
func TestHandler_GetInviteAccept(t *testing.T) {
	t.Parallel()

	t.Run("pending invitation renders the form", func(t *testing.T) {
		t.Parallel()
		f, _ := newInviteHandlerFixture(t)
		ctx := context.Background()

		inv, err := f.userSvc.CreateInvitation(ctx, "newbie@example.com", "New Bie", "admin", time.Hour)
		if err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}

		req := withChiToken(httptest.NewRequest(http.MethodGet, "/invite/"+inv.Token, nil), inv.Token)
		rec := httptest.NewRecorder()
		f.handler.GetInviteAccept(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{"newbie@example.com", "New Bie", `name="username"`, `name="confirm_password"`} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %q", want)
			}
		}
	})

	t.Run("unknown token redirects with a flash", func(t *testing.T) {
		t.Parallel()
		f, _ := newInviteHandlerFixture(t)

		req := withChiToken(httptest.NewRequest(http.MethodGet, "/invite/nope", nil), "nope")
		rec := httptest.NewRecorder()
		f.handler.GetInviteAccept(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login?flash=invite-invalid" {
			t.Errorf("Location = %q, want /login?flash=invite-invalid", loc)
		}
	})
}

// TestHandler_PostInviteAccept proves accepting creates the account even while
// registration is disabled, signs the recipient in, and consumes the link.
func TestHandler_PostInviteAccept(t *testing.T) {
	t.Parallel()

	f, sender := newInviteHandlerFixture(t)
	ctx := context.Background()

	inv, err := f.userSvc.CreateInvitation(ctx, "joiner@example.com", "Joiner", "admin", time.Hour)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	form := url.Values{}
	form.Set("username", "joiner")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	req := withChiToken(httptest.NewRequest(http.MethodPost, "/invite/"+inv.Token, strings.NewReader(form.Encode())), inv.Token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.PostInviteAccept(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302; body:\n%s", res.StatusCode, rec.Body.String())
	}
	var sessionSet bool
	for _, c := range res.Cookies() {
		if c.Name == f.cfg.Session.CookieName && c.Value != "" {
			sessionSet = true
		}
	}
	if !sessionSet {
		t.Error("session cookie was not set")
	}

	u, err := f.userStore.GetByEmail(ctx, "joiner@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if !u.IsActive || !u.EmailVerified {
		t.Errorf("accepted user active=%v verified=%v, want both true", u.IsActive, u.EmailVerified)
	}
	if len(sender.sentInvitations()) != 0 {
		t.Error("accepting an invite sent another email")
	}

	if _, err := f.userSvc.AcceptInvitation(ctx, inv.Token, "joiner2", "password123"); !errors.Is(err, user.ErrInvitationAccepted) {
		t.Errorf("replayed invite: got %v, want ErrInvitationAccepted", err)
	}
}

// TestHandler_PostInviteAccept_Validation re-renders the form with a message
// rather than creating anything when the input is unusable.
func TestHandler_PostInviteAccept_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		form    url.Values
		wantMsg string
	}{
		{
			name:    "passwords do not match",
			form:    url.Values{"username": {"mismatch"}, "password": {"password123"}, "confirm_password": {"different123"}},
			wantMsg: "The passwords do not match.",
		},
		{
			name:    "password too short",
			form:    url.Values{"username": {"shorty"}, "password": {"short"}, "confirm_password": {"short"}},
			wantMsg: "Password must be at least 8 characters.",
		},
		{
			name:    "username missing",
			form:    url.Values{"username": {""}, "password": {"password123"}, "confirm_password": {"password123"}},
			wantMsg: "Username is required.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, _ := newInviteHandlerFixture(t)
			ctx := context.Background()

			inv, err := f.userSvc.CreateInvitation(ctx, "invalid@example.com", "", "admin", time.Hour)
			if err != nil {
				t.Fatalf("CreateInvitation: %v", err)
			}

			req := withChiToken(httptest.NewRequest(http.MethodPost, "/invite/"+inv.Token, strings.NewReader(tc.form.Encode())), inv.Token)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			f.handler.PostInviteAccept(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (re-rendered form)", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.wantMsg) {
				t.Errorf("body missing %q", tc.wantMsg)
			}
			if _, err := f.userStore.GetByEmail(ctx, "invalid@example.com"); !errors.Is(err, user.ErrNotFound) {
				t.Errorf("invalid accept created a user: %v", err)
			}
		})
	}
}
