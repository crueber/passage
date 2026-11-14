package user

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
)

// inviteAcceptData is the render data for the invitation acceptance page.
type inviteAcceptData struct {
	Flash     *Flash
	Token     string
	Email     string
	Name      string
	Username  string
	CSRFToken string
}

// GetInviteAccept renders the account-creation form for an invitation link.
//
// This route is deliberately outside the registration policy: invitations are
// the way an administrator creates an account while public registration is
// off. The invitation row is the authorisation, so no registration check runs
// here.
func (h *Handler) GetInviteAccept(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	inv, err := h.users.GetPendingInvitation(r.Context(), token)
	if err != nil {
		h.redirectInviteError(w, r, err)
		return
	}

	h.render(w, r, "invite.html", inviteAcceptData{
		Token: token,
		Email: inv.Email,
		Name:  inv.Name,
		// A sensible starting point from the address; the recipient can change
		// it before the account exists.
		Username:  deriveUsername("", inv.Email),
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// PostInviteAccept creates the account an invitation describes, consumes the
// invitation, and signs the new user in. The address is fixed by the
// invitation; the recipient only chooses a username and password.
func (h *Handler) PostInviteAccept(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	inv, err := h.users.GetPendingInvitation(r.Context(), token)
	if err != nil {
		h.redirectInviteError(w, r, err)
		return
	}

	renderErr := func(msg, username, displayName string) {
		h.render(w, r, "invite.html", inviteAcceptData{
			Flash:     &Flash{Type: "error", Message: msg},
			Token:     token,
			Email:     inv.Email,
			Name:      displayName,
			Username:  username,
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
	}

	if err := r.ParseForm(); err != nil {
		renderErr("Invalid form submission.", "", "")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	if username == "" {
		renderErr("Username is required.", username, displayName)
		return
	}
	if len(displayName) > MaxDisplayNameLength {
		renderErr(fmt.Sprintf("Display name must be at most %d characters.", MaxDisplayNameLength), username, displayName)
		return
	}
	if len(password) < 8 {
		renderErr("Password must be at least 8 characters.", username, displayName)
		return
	}
	if password != confirm {
		renderErr("The passwords do not match.", username, displayName)
		return
	}

	u, err := h.users.AcceptInvitation(r.Context(), token, username, displayName, password)
	if err != nil {
		msg := "Could not create the account. Please try again."
		switch {
		case errors.Is(err, ErrUsernameTaken):
			msg = "That username is already taken."
		case errors.Is(err, ErrEmailTaken):
			msg = "An account with this email address already exists. Sign in instead."
		case errors.Is(err, ErrPasswordTooShort):
			msg = "Password must be at least 8 characters."
		case errors.Is(err, ErrNameTooLong):
			msg = fmt.Sprintf("Display name must be at most %d characters.", MaxDisplayNameLength)
		case errors.Is(err, ErrInvitationExpired), errors.Is(err, ErrInvitationAccepted), errors.Is(err, ErrInvitationNotFound):
			h.redirectInviteError(w, r, err)
			return
		}
		renderErr(msg, username, displayName)
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventRegisterSuccess,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   "invitation",
	})

	sessionToken, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, nil, r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("invite accept: create session", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/login?flash=registered", http.StatusFound)
		return
	}

	setSessionCookie(w, sessionToken, expiresAt, h.cfg)
	http.Redirect(w, r, "/", http.StatusFound)
}

// redirectInviteError sends an unusable invitation link to a page that can
// explain the problem. It never leaks whether an account exists.
func (h *Handler) redirectInviteError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvitationExpired):
		http.Redirect(w, r, "/login?flash=invite-expired", http.StatusFound)
	case errors.Is(err, ErrInvitationAccepted):
		http.Redirect(w, r, "/login?flash=invite-used", http.StatusFound)
	case errors.Is(err, ErrInvitationNotFound):
		http.Redirect(w, r, "/login?flash=invite-invalid", http.StatusFound)
	default:
		h.logger.Error("invite accept: load invitation", "error", err)
		http.Redirect(w, r, "/login?flash=error", http.StatusFound)
	}
}
