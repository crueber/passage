package user

import (
	"context"
	"errors"
	"net/http"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/settings"
)

// securityPasswordURL is where the change-password form lives. Every outcome
// returns there so the flash message appears next to the form.
const securityPasswordURL = "/passkeys?tab=password"

// passwordAuthEnabled reports the stored password-sign-in policy. The admin UI
// is the only writer; a missing setting means enabled, matching the default.
func (h *Handler) passwordAuthEnabled(ctx context.Context) bool {
	return settings.Bool(ctx, h.settings, settings.PasswordEnabled, true)
}

// PostChangePassword changes the signed-in user's password. It requires the
// current password when the account has one, so a borrowed session cannot
// silently take over the account by rotating its credential.
//
// ChangePassword revokes every session for the user (OWASP session handling).
// The handler then creates a fresh session for this browser and sets the
// cookie, so the person who just made the change stays signed in while every
// other device is logged out.
func (h *Handler) PostChangePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.passwordAuthEnabled(r.Context()) {
		http.Redirect(w, r, "/passkeys?flash=password-disabled", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, securityPasswordURL+"&flash=password-error", http.StatusFound)
		return
	}

	current := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	// Accounts created through a provider, a passkey, or a magic link have no
	// password yet: allow setting the first one without asking for a current
	// password there is none of.
	if u.PasswordHash != "" {
		if _, err := h.users.Authenticate(r.Context(), u.Username, current); err != nil {
			if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserInactive) {
				h.record(r, authlog.Event{
					Event:    authlog.EventPasswordChanged,
					Outcome:  authlog.OutcomeFailure,
					UserID:   u.ID,
					Username: u.Username,
					Detail:   "invalid current password",
				})
				http.Redirect(w, r, securityPasswordURL+"&flash=password-invalid", http.StatusFound)
				return
			}
			h.logger.Error("password: verify current password", "user_id", u.ID, "error", err)
			http.Redirect(w, r, securityPasswordURL+"&flash=password-error", http.StatusFound)
			return
		}
	}

	if len(newPassword) < 8 {
		http.Redirect(w, r, securityPasswordURL+"&flash=password-too-short", http.StatusFound)
		return
	}
	if newPassword != confirm {
		http.Redirect(w, r, securityPasswordURL+"&flash=password-mismatch", http.StatusFound)
		return
	}

	if err := h.users.ChangePassword(r.Context(), u.ID, newPassword); err != nil {
		if errors.Is(err, ErrPasswordTooShort) {
			http.Redirect(w, r, securityPasswordURL+"&flash=password-too-short", http.StatusFound)
			return
		}
		h.logger.Error("password: change", "user_id", u.ID, "error", err)
		http.Redirect(w, r, securityPasswordURL+"&flash=password-error", http.StatusFound)
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventPasswordChanged,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
	})

	// ChangePassword revoked every session, this one included. Issue a new
	// session so the user stays signed in here; other devices stay logged out.
	token, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, nil, r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("password: create replacement session", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/login?flash=password-changed", http.StatusFound)
		return
	}
	setSessionCookie(w, token, expiresAt, h.cfg)
	http.Redirect(w, r, securityPasswordURL+"&flash=password-changed", http.StatusFound)
}
