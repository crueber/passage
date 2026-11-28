package webauthn

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

type passkeysData struct {
	web.Themed
	User        *user.User
	Credentials []*Credential
	Flash       *user.Flash
	CSRFToken   string

	// ActiveTab is "passkeys" (default), "mfa", or "password". The parts of
	// this page are separate tasks, so each gets its own tab rather than one
	// long scroll.
	ActiveTab string

	// PasswordEnabled mirrors the global password-sign-in policy; when false
	// the Password tab is not rendered.
	PasswordEnabled bool

	// HasPassword says whether this account already has a password, so the form
	// can ask for it before replacing it (or offer to set the first one).
	HasPassword bool

	// Two-factor state, read from the MFA service. The page renders the TOTP
	// section from these three fields; the forms POST to /mfa/* (owned by the
	// user package), so this page never needs the MFA store directly.
	MFAEnabled        bool
	MFAEnabledAt      time.Time
	MFARemainingCodes int
}

// GetPasskeys renders the passkey management page.
func (h *Handler) GetPasskeys(w http.ResponseWriter, r *http.Request) {
	u, ok := session.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	creds, err := h.credStore.ListByUser(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("webauthn: list credentials", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var flash *user.Flash
	switch r.URL.Query().Get("flash") {
	case "deleted":
		flash = &user.Flash{Type: "success", Message: "Passkey removed."}
	case "error":
		flash = &user.Flash{Type: "error", Message: "An error occurred."}
	case "mfa-enabled":
		flash = &user.Flash{Type: "success", Message: "Two-factor authentication is on. Store your recovery codes somewhere safe."}
	case "mfa-disabled":
		flash = &user.Flash{Type: "success", Message: "Two-factor authentication is off."}
	case "mfa-codes-regenerated":
		flash = &user.Flash{Type: "success", Message: "New recovery codes generated. All old codes no longer work."}
	case "mfa-on":
		flash = &user.Flash{Type: "info", Message: "Two-factor authentication is already enabled."}
	case "mfa-required":
		flash = &user.Flash{Type: "info", Message: "An administrator requires two-factor authentication."}
	case "mfa-password-invalid":
		flash = &user.Flash{Type: "error", Message: "Your password was incorrect. Nothing was changed."}
	case "password-changed":
		flash = &user.Flash{Type: "success", Message: "Password changed. Every other session has been signed out."}
	case "password-invalid":
		flash = &user.Flash{Type: "error", Message: "Your current password was incorrect. Nothing was changed."}
	case "password-too-short":
		flash = &user.Flash{Type: "error", Message: "New password must be at least 8 characters."}
	case "password-mismatch":
		flash = &user.Flash{Type: "error", Message: "The new passwords do not match."}
	case "password-error":
		flash = &user.Flash{Type: "error", Message: "Could not change your password. Please try again."}
	case "password-disabled":
		flash = &user.Flash{Type: "error", Message: "Password sign-in is disabled on this instance."}
	}

	// A failure to read MFA state must not take down the Security page: render
	// it as "not enabled" and log. The enrollment flow re-checks server-side, so
	// a stale badge cannot turn into a broken credential.
	var status mfa.Status
	if h.mfa != nil {
		st, err := h.mfa.Status(r.Context(), u.ID)
		if err != nil {
			h.logger.Warn("webauthn: read mfa status", "user_id", u.ID, "error", err)
		} else {
			status = st
		}
	}

	activeTab := "passkeys"
	passwordEnabled := h.passwordEnabled(r.Context())
	switch r.URL.Query().Get("tab") {
	case "mfa":
		activeTab = "mfa"
	case "password":
		if passwordEnabled {
			activeTab = "password"
		}
	}

	h.render(w, r, "passkeys.html", passkeysData{
		Themed:            web.NewThemed(u.Theme),
		User:              u,
		Credentials:       creds,
		Flash:             flash,
		CSRFToken:         csrf.TokenFromContext(r.Context()),
		ActiveTab:         activeTab,
		PasswordEnabled:   passwordEnabled,
		HasPassword:       u.PasswordHash != "",
		MFAEnabled:        status.Enabled,
		MFAEnabledAt:      status.EnabledAt,
		MFARemainingCodes: status.RemainingCodes,
	})
}

// PostDeletePasskey removes a passkey credential by ID (if it belongs to the logged-in user).
func (h *Handler) PostDeletePasskey(w http.ResponseWriter, r *http.Request) {
	u, ok := session.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	credID := chi.URLParam(r, "id")
	ctx := r.Context()

	// Verify the credential belongs to this user before deleting.
	cred, err := h.credStore.GetByID(ctx, credID)
	if err != nil {
		h.logger.Error("webauthn: get credential for delete", "id", credID, "error", err)
		http.Redirect(w, r, "/passkeys?flash=error", http.StatusFound)
		return
	}
	if cred.UserID != u.ID {
		h.logger.Warn("webauthn: credential ownership mismatch", "user_id", u.ID, "cred_user_id", cred.UserID)
		http.Redirect(w, r, "/passkeys?flash=error", http.StatusFound)
		return
	}

	if err := h.credStore.Delete(ctx, credID); err != nil {
		h.logger.Error("webauthn: delete credential", "id", credID, "error", err)
		http.Redirect(w, r, "/passkeys?flash=error", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/passkeys?flash=deleted", http.StatusFound)
}
