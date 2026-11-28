package user

import (
	"errors"
	"net/http"
	"strings"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/mfa"
)

// mfaLoginData is the template data for the second-factor form.
type mfaLoginData struct {
	Flash     *Flash
	CSRFToken string
	Username  string
	Tagline   string
	Wordmark  string
	// PasskeyAvailable is decided server-side: the passkey button renders only
	// when a passkey can actually complete this challenge.
	PasskeyAvailable bool
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
	passkey := false
	if u, err := h.users.GetByID(r.Context(), ch.UserID); err == nil {
		username = u.Username
		passkey = h.passkeySecondFactorAvailable(r.Context(), u.ID)
	}
	h.renderMFALogin(w, r, username, passkey, nil)
}

// PostMFALogin verifies a TOTP or recovery code and, only then, creates the
// session exactly as the password flow would.
func (h *Handler) PostMFALogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login/mfa", http.StatusFound)
		return
	}

	ch, u, err := h.mfaChallengeUser(r)
	if err != nil {
		clearMFACookie(w, h.cfg)
		switch {
		case errors.Is(err, errMFAAccountInactive):
			http.Redirect(w, r, "/login?flash=account-inactive", http.StatusFound)
		case errors.Is(err, errMFALoadUser):
			http.Redirect(w, r, "/login?flash=error", http.StatusFound)
		default:
			http.Redirect(w, r, "/login?flash=mfa-expired", http.StatusFound)
		}
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
			h.renderMFALogin(w, r, u.Username, h.passkeySecondFactorAvailable(r.Context(), u.ID), &Flash{Type: "error", Message: lockedLoginMessage(status.Remaining)})
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
		h.renderMFALogin(w, r, u.Username, h.passkeySecondFactorAvailable(r.Context(), u.ID), &Flash{Type: "error", Message: "That code is not valid. Please try again."})
		return
	}

	dest, err := h.completeMFAChallenge(w, r, ch, u, method)
	if err != nil {
		if errors.Is(err, errMFAConsumeChallenge) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/login?flash=error", http.StatusFound)
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// renderMFALogin renders the second-factor form. The username only labels the
// page; it is best-effort and never changes the flow.
func (h *Handler) renderMFALogin(w http.ResponseWriter, r *http.Request, username string, passkey bool, flash *Flash) {
	h.render(w, r, "login_mfa.html", mfaLoginData{
		Flash:            flash,
		CSRFToken:        csrf.TokenFromContext(r.Context()),
		Username:         username,
		PasskeyAvailable: passkey,
		Tagline:          h.tagline(r.Context()),
		Wordmark:         h.wordmark(r.Context()),
	})
}

// isExpectedMFAFailure reports whether err is one of the routine "the code was
// wrong" outcomes, as opposed to a store or clock problem worth logging.
func isExpectedMFAFailure(err error) bool {
	return errors.Is(err, mfa.ErrInvalidCode) ||
		errors.Is(err, mfa.ErrReplay) ||
		errors.Is(err, mfa.ErrNotEnabled)
}
