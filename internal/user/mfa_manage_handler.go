package user

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/skip2/go-qrcode"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/web"
)

// mfaSetupData is the template data for the enrollment page.
type mfaSetupData struct {
	web.Themed
	User      *User
	Flash     *Flash
	CSRFToken string
	// Display is the base32 secret grouped in fours for manual entry; URI is
	// the same value as an otpauth:// link. The raw ungrouped secret is not
	// rendered: neither form needs it.
	Display  string
	URI      string
	Required bool
}

// mfaCodesData is the one-time recovery-code page.
type mfaCodesData struct {
	web.Themed
	User        *User
	Flash       *Flash
	CSRFToken   string
	Codes       []string
	Regenerated bool
}

// MFARoutes registers the enrollment and management endpoints. The router must
// already have RequireSession and CSRF middleware applied, and must NOT have the
// RequireMFA gate: these routes are the way out of that gate.
func (h *Handler) MFARoutes(r chi.Router, limiter *ratelimit.Limiter) {
	// limiter may be nil in tests; production always passes the login limiter,
	// so a code-guessing loop is bounded per client address exactly like /login.
	wrap := func(fn http.HandlerFunc) http.HandlerFunc { return fn }
	if limiter != nil {
		mw := ratelimit.Middleware(limiter)
		wrap = func(fn http.HandlerFunc) http.HandlerFunc { return mw(fn).ServeHTTP }
	}

	r.Get("/mfa/setup", h.GetMFASetup)
	r.Get("/mfa/qr", h.GetMFAQR)
	r.Post("/mfa/setup", wrap(h.PostMFASetup))
	r.Post("/mfa/disable", wrap(h.PostMFADisable))
	r.Post("/mfa/recovery-codes", wrap(h.PostMFARecoveryCodes))
}

// GetMFAQR serves the provisioning QR for the pending enrollment as a PNG.
//
// A route rather than an inline data URI: html/template refuses the data:
// scheme in an src attribute (it renders #ZgotmplZ), and serving the image
// keeps the template free of an escaping bypass. The response is never cached;
// it is only meaningful while an enrollment is pending.
func (h *Handler) GetMFAQR(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil || h.mfa == nil {
		http.NotFound(w, r)
		return
	}

	enr, err := h.mfa.PendingEnrollment(r.Context(), u.ID, u.Username)
	if err != nil {
		// No pending enrollment (enabled, reset, or never started) is a 404. The
		// setup page is the only expected referrer.
		if !errors.Is(err, mfa.ErrNotPending) && !errors.Is(err, mfa.ErrNotFound) {
			h.logger.Error("mfa: qr pending enrollment", "user_id", u.ID, "error", err)
		}
		http.NotFound(w, r)
		return
	}

	png, err := qrcode.Encode(enr.URI, qrcode.Medium, 256)
	if err != nil {
		h.logger.Error("mfa: encode qr", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// GetMFASetup starts (or restarts) enrollment and shows the pending secret.
// The secret is rotated on every visit: an enrollment that was never confirmed
// must never be a credential the user has forgotten about.
func (h *Handler) GetMFASetup(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if h.mfa == nil {
		http.Redirect(w, r, "/passkeys?tab=mfa", http.StatusFound)
		return
	}

	st, err := h.mfa.Status(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("mfa: status before setup", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if st.Enabled {
		http.Redirect(w, r, "/passkeys?tab=mfa&flash=mfa-on", http.StatusFound)
		return
	}

	enr, err := h.mfa.BeginEnrollment(r.Context(), u.ID, u.Username)
	if err != nil {
		// A concurrent tab finished enrollment between the status check and the
		// upsert: send it to the Security page rather than reporting an error.
		if errors.Is(err, mfa.ErrNotPending) {
			http.Redirect(w, r, "/passkeys?tab=mfa&flash=mfa-on", http.StatusFound)
			return
		}
		h.logger.Error("mfa: begin enrollment", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderMFASetup(w, r, u, enr, r.URL.Query().Get("required") == "1", nil)
}

// PostMFASetup verifies the first TOTP code, enables the factor, and renders
// the recovery codes once.
func (h *Handler) PostMFASetup(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if h.mfa == nil {
		http.Redirect(w, r, "/passkeys?tab=mfa", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/mfa/setup", http.StatusFound)
		return
	}

	required := r.FormValue("required") == "1"
	codes, err := h.mfa.ConfirmEnrollment(r.Context(), u.ID, strings.TrimSpace(r.FormValue("code")))
	if err != nil {
		msg := "That code is not valid. Check your authenticator app and try again."
		switch {
		case errors.Is(err, mfa.ErrNotPending):
			// Already enabled: a second POST (double submit, stale tab) must not
			// rotate the working credential.
			http.Redirect(w, r, "/passkeys?tab=mfa&flash=mfa-on", http.StatusFound)
			return
		case errors.Is(err, mfa.ErrNotFound):
			// Pending row vanished (admin reset mid-enrollment): start over.
			http.Redirect(w, r, "/mfa/setup", http.StatusFound)
			return
		case !errors.Is(err, mfa.ErrInvalidCode):
			h.logger.Error("mfa: confirm enrollment", "user_id", u.ID, "error", err)
		}
		h.record(r, authlog.Event{
			Event:    authlog.EventMFAFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "invalid code",
		})

		enr, pendErr := h.mfa.PendingEnrollment(r.Context(), u.ID, u.Username)
		if pendErr != nil {
			h.logger.Error("mfa: re-read pending enrollment", "user_id", u.ID, "error", pendErr)
			http.Redirect(w, r, "/mfa/setup", http.StatusFound)
			return
		}
		h.renderMFASetup(w, r, u, enr, required, &Flash{Type: "error", Message: msg})
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventMFAEnrolled,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   "totp",
	})
	h.render(w, r, "mfa_recovery_codes.html", mfaCodesData{
		Themed:    web.NewThemed(u.Theme),
		User:      u,
		CSRFToken: csrf.TokenFromContext(r.Context()),
		Codes:     codes,
	})
}

// renderMFASetup renders the enrollment page for a pending secret.
func (h *Handler) renderMFASetup(w http.ResponseWriter, r *http.Request, u *User, enr mfa.Enrollment, required bool, flash *Flash) {
	h.render(w, r, "mfa_setup.html", mfaSetupData{
		Themed:    web.NewThemed(u.Theme),
		User:      u,
		Flash:     flash,
		CSRFToken: csrf.TokenFromContext(r.Context()),
		Display:   enr.Display,
		URI:       enr.URI,
		Required:  required,
	})
}

// PostMFADisable removes the second factor after re-authenticating with the
// current password.
func (h *Handler) PostMFADisable(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if h.mfa == nil {
		http.Redirect(w, r, "/passkeys?tab=mfa", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/passkeys?tab=mfa", http.StatusFound)
		return
	}

	if err := h.reauthenticate(r.Context(), u, r.FormValue("password")); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			http.Redirect(w, r, "/passkeys?tab=mfa&flash=mfa-password-invalid", http.StatusFound)
			return
		}
		h.logger.Error("mfa: re-authenticate for disable", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := h.mfa.Disable(r.Context(), u.ID); err != nil {
		h.logger.Error("mfa: disable", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/passkeys?tab=mfa&flash=error", http.StatusFound)
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventMFADisabled,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
	})
	http.Redirect(w, r, "/passkeys?tab=mfa&flash=mfa-disabled", http.StatusFound)
}

// PostMFARecoveryCodes issues a fresh set of recovery codes, invalidating the
// old ones, after re-authenticating with the current password.
func (h *Handler) PostMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if h.mfa == nil {
		http.Redirect(w, r, "/passkeys?tab=mfa", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/passkeys?tab=mfa", http.StatusFound)
		return
	}

	if err := h.reauthenticate(r.Context(), u, r.FormValue("password")); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			http.Redirect(w, r, "/passkeys?tab=mfa&flash=mfa-password-invalid", http.StatusFound)
			return
		}
		h.logger.Error("mfa: re-authenticate for recovery codes", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	codes, err := h.mfa.RegenerateRecoveryCodes(r.Context(), u.ID)
	if err != nil {
		if errors.Is(err, mfa.ErrNotEnabled) {
			http.Redirect(w, r, "/passkeys?tab=mfa&flash=error", http.StatusFound)
			return
		}
		h.logger.Error("mfa: regenerate recovery codes", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/passkeys?tab=mfa&flash=error", http.StatusFound)
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventMFACodesRegenerated,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
	})
	h.render(w, r, "mfa_recovery_codes.html", mfaCodesData{
		Themed:      web.NewThemed(u.Theme),
		User:        u,
		CSRFToken:   csrf.TokenFromContext(r.Context()),
		Codes:       codes,
		Regenerated: true,
	})
}

// reauthenticate verifies the signed-in user's password before a sensitive MFA
// change. It reuses the same bcrypt comparison as login, so a wrong password is
// indistinguishable from a wrong password anywhere else.
func (h *Handler) reauthenticate(ctx context.Context, u *User, password string) error {
	if password == "" {
		return ErrInvalidCredentials
	}
	if _, err := h.users.Authenticate(ctx, u.Username, password); err != nil {
		return err
	}
	return nil
}
