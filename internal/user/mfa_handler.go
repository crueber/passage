package user

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/ratelimit"
)

const (
	// MFACookieName is the pending second-factor cookie. It is deliberately not
	// the session cookie: RequireSession never reads it and no handler treats
	// it as authentication. It only names a row in mfa_challenges, which grants
	// nothing until a code is verified.
	MFACookieName = "passage_mfa"

	// SettingRequireMFA is the settings-store key behind the global "require
	// two-factor authentication" policy. An explicit "true"/"false" wins over
	// the auth.require_mfa config default; see Handler.mfaRequired.
	SettingRequireMFA = "auth_require_mfa"
)

// mfaCookieName returns the pending-challenge cookie name, applying the
// __Host- prefix when secure cookies are enabled — the same browser-enforced
// invariant the session cookie uses, so a sibling subdomain cannot shadow it.
func mfaCookieName(cfg *config.Config) string {
	if cfg.Session.CookieSecure {
		return "__Host-" + MFACookieName
	}
	return MFACookieName
}

// setMFACookie writes the pending-challenge cookie. It expires with the
// challenge row (five minutes) and is HttpOnly, so no script can read it.
func setMFACookie(w http.ResponseWriter, token string, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookieName(cfg),
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(mfa.ChallengeTTL),
		MaxAge:   int(mfa.ChallengeTTL / time.Second),
		HttpOnly: true,
		Secure:   cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearMFACookie expires the pending-challenge cookie.
func clearMFACookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookieName(cfg),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ─── Login challenge ─────────────────────────────────────────────────────────

// mfaLoginData is the template data for the second-factor form.
type mfaLoginData struct {
	Flash     *Flash
	CSRFToken string
	Username  string
}

// startMFAChallenge issues a pending challenge after a correct password and
// sends the browser to the second-factor form. No session is created here or
// anywhere before the factor is verified.
func (h *Handler) startMFAChallenge(w http.ResponseWriter, r *http.Request, u *User, dest string) {
	token, err := h.mfa.CreateChallenge(r.Context(), u.ID, dest)
	if err != nil {
		h.logger.Error("mfa: create challenge", "user_id", u.ID, "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventLoginFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "mfa challenge create failed",
		})
		h.renderLoginError(w, r, "An error occurred. Please try again.", dest, u.Username)
		return
	}

	setMFACookie(w, token, h.cfg)
	h.record(r, authlog.Event{
		Event:    authlog.EventMFAChallenge,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   "password verified",
	})
	http.Redirect(w, r, "/login/mfa", http.StatusFound)
}

// liveChallenge loads the challenge named by the pending cookie, or reports
// false when there is none, it has expired, or MFA is not wired.
func (h *Handler) liveChallenge(r *http.Request) (*mfa.Challenge, bool) {
	if h.mfa == nil {
		return nil, false
	}
	cookie, err := r.Cookie(mfaCookieName(h.cfg))
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	ch, err := h.mfa.Challenge(r.Context(), cookie.Value)
	if err != nil {
		// An expired row is swept hourly; deleting it now keeps one abandoned
		// sign-in from lingering. Never log the token: it is a bearer value.
		if errors.Is(err, mfa.ErrChallengeExpired) {
			if derr := h.mfa.ConsumeChallenge(r.Context(), cookie.Value); derr != nil {
				h.logger.Warn("mfa: delete expired challenge", "error", derr)
			}
		}
		return nil, false
	}
	return ch, true
}

// GetMFALogin renders the second-factor form. Without a live challenge there is
// nothing to verify against, so the user is sent back to the start of sign-in.
func (h *Handler) GetMFALogin(w http.ResponseWriter, r *http.Request) {
	ch, ok := h.liveChallenge(r)
	if !ok {
		clearMFACookie(w, h.cfg)
		http.Redirect(w, r, "/login?flash=mfa-expired", http.StatusFound)
		return
	}
	username := ""
	if u, err := h.users.GetByID(r.Context(), ch.UserID); err == nil {
		username = u.Username
	}
	h.renderMFALogin(w, r, username, nil)
}

// PostMFALogin verifies a TOTP or recovery code and, only then, creates the
// session exactly as the password flow would.
func (h *Handler) PostMFALogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login/mfa", http.StatusFound)
		return
	}

	ch, ok := h.liveChallenge(r)
	if !ok {
		clearMFACookie(w, h.cfg)
		http.Redirect(w, r, "/login?flash=mfa-expired", http.StatusFound)
		return
	}

	// Load the account first: it is needed for the session, for the failure
	// event's username, and to refuse an account that was deactivated between
	// the password and the code (the challenge must not outlive the account).
	u, err := h.users.GetByID(r.Context(), ch.UserID)
	if err != nil {
		h.logger.Error("mfa: load user for challenge", "user_id", ch.UserID, "error", err)
		clearMFACookie(w, h.cfg)
		http.Redirect(w, r, "/login?flash=error", http.StatusFound)
		return
	}
	if !u.IsActive {
		h.record(r, authlog.Event{
			Event:    authlog.EventMFAFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "account inactive",
		})
		clearMFACookie(w, h.cfg)
		http.Redirect(w, r, "/login?flash=account-inactive", http.StatusFound)
		return
	}

	// The second step is a 6-digit secret: without a per-account limit it is the
	// cheapest half of the pair to brute force. Reuse the password throttle so a
	// run of bad codes locks the account exactly like a run of bad passwords.
	if h.throttle != nil {
		if status, terr := h.throttle.Status(r.Context(), u.Username); terr != nil {
			// Fail open: a throttle-store problem must not block a valid user.
			h.logger.Warn("mfa: throttle status", "error", terr)
		} else if status.Locked {
			h.record(r, authlog.Event{
				Event:    authlog.EventMFAFailure,
				Outcome:  authlog.OutcomeThrottled,
				UserID:   u.ID,
				Username: u.Username,
				Detail:   "account locked",
			})
			h.renderMFALogin(w, r, u.Username, &Flash{Type: "error", Message: lockedLoginMessage(status.Remaining)})
			return
		}
	}

	code := strings.TrimSpace(r.FormValue("code"))
	method, err := h.mfa.Verify(r.Context(), ch.UserID, code)
	if err != nil {
		if h.throttle != nil {
			if _, terr := h.throttle.RecordFailure(r.Context(), u.Username); terr != nil {
				h.logger.Warn("mfa: record failure", "error", terr)
			}
		}
		// Log only the unexpected failures; a wrong, spent, or replayed code is
		// routine and must not fill the log. The code itself is never logged.
		if !isExpectedMFAFailure(err) {
			h.logger.Error("mfa: verify code", "user_id", u.ID, "error", err)
		}
		// A generic message: an unknown code, a spent code, and a replayed TOTP
		// step must be indistinguishable to the caller.
		h.record(r, authlog.Event{
			Event:    authlog.EventMFAFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "invalid code",
		})
		h.renderMFALogin(w, r, u.Username, &Flash{Type: "error", Message: "That code is not valid. Please try again."})
		return
	}

	// The challenge grants exactly one session. Deleting it is part of the
	// verification, not cleanup: if it cannot be deleted, no session is created
	// (the factor itself is still single-use, but the pending password proof
	// must not survive a completed sign-in).
	if err := h.mfa.ConsumeChallenge(r.Context(), ch.Token); err != nil {
		h.logger.Error("mfa: consume challenge", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	token, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, h.appIDFromReturnTarget(r.Context(), ch.ReturnTo), r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("mfa: create session after verification", "user_id", u.ID, "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventLoginFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "session create failed",
		})
		http.Redirect(w, r, "/login?flash=error", http.StatusFound)
		return
	}

	if h.throttle != nil {
		if terr := h.throttle.Reset(r.Context(), u.Username); terr != nil {
			h.logger.Warn("mfa: reset throttle", "error", terr)
		}
	}

	setSessionCookie(w, token, expiresAt, h.cfg)
	clearMFACookie(w, h.cfg)
	clearReturnCookieIfPresent(w, r, h.cfg)
	h.record(r, authlog.Event{
		Event:    authlog.EventMFASuccess,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   method,
	})

	dest := ch.ReturnTo
	if !safeReturnPath(dest) {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// renderMFALogin renders the second-factor form. The username only labels the
// page; it is best-effort and never changes the flow.
func (h *Handler) renderMFALogin(w http.ResponseWriter, r *http.Request, username string, flash *Flash) {
	h.render(w, r, "login_mfa.html", mfaLoginData{
		Flash:     flash,
		CSRFToken: csrf.TokenFromContext(r.Context()),
		Username:  username,
	})
}

// ─── Enrollment and management ───────────────────────────────────────────────

// mfaSetupData is the template data for the enrollment page.
type mfaSetupData struct {
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
	r.Post("/mfa/setup", wrap(h.PostMFASetup))
	r.Post("/mfa/disable", wrap(h.PostMFADisable))
	r.Post("/mfa/recovery-codes", wrap(h.PostMFARecoveryCodes))
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
		http.Redirect(w, r, "/passkeys", http.StatusFound)
		return
	}

	st, err := h.mfa.Status(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("mfa: status before setup", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if st.Enabled {
		http.Redirect(w, r, "/passkeys?flash=mfa-on", http.StatusFound)
		return
	}

	enr, err := h.mfa.BeginEnrollment(r.Context(), u.ID, u.Username)
	if err != nil {
		// A concurrent tab finished enrollment between the status check and the
		// upsert: send it to the Security page rather than reporting an error.
		if errors.Is(err, mfa.ErrNotPending) {
			http.Redirect(w, r, "/passkeys?flash=mfa-on", http.StatusFound)
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
		http.Redirect(w, r, "/passkeys", http.StatusFound)
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
			http.Redirect(w, r, "/passkeys?flash=mfa-on", http.StatusFound)
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
		User:      u,
		CSRFToken: csrf.TokenFromContext(r.Context()),
		Codes:     codes,
	})
}

// renderMFASetup renders the enrollment page for a pending secret.
func (h *Handler) renderMFASetup(w http.ResponseWriter, r *http.Request, u *User, enr mfa.Enrollment, required bool, flash *Flash) {
	h.render(w, r, "mfa_setup.html", mfaSetupData{
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
		http.Redirect(w, r, "/passkeys", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/passkeys", http.StatusFound)
		return
	}

	if err := h.reauthenticate(r.Context(), u, r.FormValue("password")); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			http.Redirect(w, r, "/passkeys?flash=mfa-password-invalid", http.StatusFound)
			return
		}
		h.logger.Error("mfa: re-authenticate for disable", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := h.mfa.Disable(r.Context(), u.ID); err != nil {
		h.logger.Error("mfa: disable", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/passkeys?flash=error", http.StatusFound)
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventMFADisabled,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
	})
	http.Redirect(w, r, "/passkeys?flash=mfa-disabled", http.StatusFound)
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
		http.Redirect(w, r, "/passkeys", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/passkeys", http.StatusFound)
		return
	}

	if err := h.reauthenticate(r.Context(), u, r.FormValue("password")); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			http.Redirect(w, r, "/passkeys?flash=mfa-password-invalid", http.StatusFound)
			return
		}
		h.logger.Error("mfa: re-authenticate for recovery codes", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	codes, err := h.mfa.RegenerateRecoveryCodes(r.Context(), u.ID)
	if err != nil {
		if errors.Is(err, mfa.ErrNotEnabled) {
			http.Redirect(w, r, "/passkeys?flash=mfa-on", http.StatusFound)
			return
		}
		h.logger.Error("mfa: regenerate recovery codes", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/passkeys?flash=error", http.StatusFound)
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventMFACodesRegenerated,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
	})
	h.render(w, r, "mfa_recovery_codes.html", mfaCodesData{
		User:        u,
		CSRFToken:   csrf.TokenFromContext(r.Context()),
		Codes:       codes,
		Regenerated: true,
	})
}

// isExpectedMFAFailure reports whether err is one of the routine "the code was
// wrong" outcomes, as opposed to a store or clock problem worth logging.
func isExpectedMFAFailure(err error) bool {
	return errors.Is(err, mfa.ErrInvalidCode) ||
		errors.Is(err, mfa.ErrReplay) ||
		errors.Is(err, mfa.ErrNotEnabled)
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

// clearReturnCookieIfPresent expires the passage_rd cookie consumed by a
// completed sign-in. Harmless when the cookie was never set.
func clearReturnCookieIfPresent(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	if _, err := r.Cookie("passage_rd"); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "passage_rd",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
