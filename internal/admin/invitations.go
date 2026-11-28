package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// Invitation expiry bounds for the admin form. A link that lives too long is
// an unauthenticated path into the instance; a shorter one is easy to outlive
// an inbox check.
const (
	invitationExpiryDaysDefault = 7
	invitationExpiryDaysMax     = 30
)

// inviteUserData is the render data for the invite form and the pending list.
type inviteUserData struct {
	basePage
	Invitations    []*user.Invitation
	Email          string
	Name           string
	ExpiryDays     int
	SMTPConfigured bool
}

// GetInviteUser renders the invitation form and the list of pending invites.
func (h *Handler) GetInviteUser(w http.ResponseWriter, r *http.Request) {
	invitations, err := h.userSvc.ListPendingInvitations(r.Context())
	if err != nil {
		// The form is still useful without the list; a query failure must not
		// block the page.
		h.logger.Warn("admin: list pending invitations", "error", err)
	}

	h.render(w, r, "admin-invite-user", inviteUserData{
		basePage:       h.baseQueryFlash(r, "users"),
		Invitations:    invitations,
		ExpiryDays:     invitationExpiryDaysDefault,
		SMTPConfigured: h.smtpConfigured(r.Context()),
	})
}

// PostInviteUser creates an invitation and emails the link. It deliberately
// writes no user row: the account is created when the recipient accepts.
func (h *Handler) PostInviteUser(w http.ResponseWriter, r *http.Request) {
	renderErr := func(msg, emailAddr, name string, days int) {
		pending, err := h.userSvc.ListPendingInvitations(r.Context())
		if err != nil {
			h.logger.Warn("admin: list pending invitations", "error", err)
		}
		h.render(w, r, "admin-invite-user", inviteUserData{
			basePage:       h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			Invitations:    pending,
			Email:          emailAddr,
			Name:           name,
			ExpiryDays:     days,
			SMTPConfigured: h.smtpConfigured(r.Context()),
		})
	}

	if err := r.ParseForm(); err != nil {
		renderErr("Invalid form submission.", "", "", invitationExpiryDaysDefault)
		return
	}

	emailAddr := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	days, err := strconv.Atoi(strings.TrimSpace(r.FormValue("expiry_days")))
	if err != nil || days < 1 || days > invitationExpiryDaysMax {
		renderErr(fmt.Sprintf("Expiry must be a whole number of days between 1 and %d.", invitationExpiryDaysMax), emailAddr, name, invitationExpiryDaysDefault)
		return
	}
	if emailAddr == "" || !strings.Contains(emailAddr, "@") {
		renderErr("Enter a valid email address.", emailAddr, name, days)
		return
	}
	if !h.smtpConfigured(r.Context()) {
		renderErr("Invitations are sent by email, so SMTP must be configured first (Settings → Email).", emailAddr, name, days)
		return
	}

	invitedBy := ""
	if actingUser, ok := session.UserFromContext(r.Context()); ok && actingUser != nil {
		invitedBy = actingUser.Name
		if invitedBy == "" {
			invitedBy = actingUser.Username
		}
	}

	ttl := time.Duration(days) * 24 * time.Hour
	inv, err := h.userSvc.CreateInvitation(r.Context(), emailAddr, name, invitedBy, ttl)
	if err != nil {
		msg := "Could not create the invitation. Please try again."
		switch {
		case errors.Is(err, user.ErrEmailTaken):
			msg = "An account with that email already exists."
		case errors.Is(err, user.ErrEmailRequired):
			msg = "Enter a valid email address."
		case errors.Is(err, user.ErrSMTPNotConfigured):
			msg = "Invitations are sent by email, so SMTP must be configured first (Settings → Email)."
		default:
			h.logger.Error("admin: create invitation", "email", emailAddr, "error", err)
		}
		renderErr(msg, emailAddr, name, days)
		return
	}

	inviteURL := h.publicBaseURL(r) + "/invite/" + inv.Token

	if err := h.mailer.SendInvite(r.Context(), inv.Email, inv.Name, invitedBy, inviteURL, ttl); err != nil {
		// No mail means no usable invitation: remove the row so a retry does
		// not silently replace a link nobody received.
		h.logger.Warn("admin: send invitation email", "invitation_id", inv.ID, "error", err)
		if revokeErr := h.userSvc.RevokeInvitation(r.Context(), inv.ID); revokeErr != nil {
			h.logger.Error("admin: revoke unsent invitation", "invitation_id", inv.ID, "error", revokeErr)
		}
		renderErr("Could not send the invitation email. Check the SMTP settings and try again.", emailAddr, name, days)
		return
	}

	h.logAudit(r, AuditActionUserInvite, "invitation", inv.ID, inv.Email)
	http.Redirect(w, r, "/admin/users/invite?flash=invited", http.StatusFound)
}

// PostRevokeInvitation deletes a pending invitation, invalidating its link.
func (h *Handler) PostRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.userSvc.RevokeInvitation(r.Context(), id); err != nil {
		if errors.Is(err, user.ErrInvitationNotFound) {
			http.Redirect(w, r, "/admin/users/invite", http.StatusFound)
			return
		}
		h.logger.Error("admin: revoke invitation", "invitation_id", id, "error", err)
		http.Redirect(w, r, "/admin/users/invite?flash=error", http.StatusFound)
		return
	}

	h.logAudit(r, AuditActionUserInviteRevoke, "invitation", id, "")
	http.Redirect(w, r, "/admin/users/invite?flash=invite-revoked", http.StatusFound)
}
