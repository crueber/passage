package user

import (
	"errors"
	"net/http"
	"strings"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
)

// loginData is the template data for the login page.
type loginData struct {
	Flash             *Flash
	RedirectTo        string
	Username          string
	AllowRegistration bool
	AllowPassword     bool
	AllowPasskey      bool
	AllowMagicLink    bool
	AllowProviders    []ProviderButton
	Tagline           string
	Wordmark          string
	CSRFToken         string
}

// GetLogin renders the login form.
func (h *Handler) GetLogin(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	flashMsg := r.URL.Query().Get("flash")
	var flash *Flash
	if flashMsg != "" {
		flash = flashFromCode(flashMsg)
	}

	h.render(w, r, "login.html", loginData{
		Flash:             flash,
		RedirectTo:        rd,
		AllowRegistration: h.registrationAllowed(r.Context()),
		AllowPassword:     isAuthMethodEnabled(r.Context(), h.settings, SettingPasswordEnabled),
		AllowPasskey:      isAuthMethodEnabled(r.Context(), h.settings, SettingPasskeyEnabled),
		AllowMagicLink:    isAuthMethodEnabled(r.Context(), h.settings, SettingMagicLinkEnabled),
		AllowProviders:    h.providerButtons(r.Context()),
		Tagline:           h.tagline(r.Context()),
		Wordmark:          h.wordmark(r.Context()),
		CSRFToken:         csrf.TokenFromContext(r.Context()),
	})
}

// PostLogin handles credential submission.
func (h *Handler) PostLogin(w http.ResponseWriter, r *http.Request) {
	if !isAuthMethodEnabled(r.Context(), h.settings, SettingPasswordEnabled) {
		http.Error(w, "Password login is disabled.", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderLoginError(w, r, "Invalid form submission.", r.FormValue("rd"), r.FormValue("username"))
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	rd := r.FormValue("rd")

	// Per-account throttle check runs before password verification. A locked
	// account — real or unknown — gets the same generic page and never reaches
	// bcrypt, so the lock is not an account-existence oracle.
	if h.throttle != nil {
		status, err := h.throttle.Status(r.Context(), username)
		if err != nil {
			// Fail open: a throttle-store problem must not block every login.
			h.logger.Warn("login throttle status", "error", err)
		} else if status.Locked {
			h.record(r, authlog.Event{
				Event:    authlog.EventLoginThrottled,
				Outcome:  authlog.OutcomeThrottled,
				Username: username,
				Detail:   "account locked",
			})
			h.renderLoginError(w, r, lockedLoginMessage(status.Remaining), rd, username)
			return
		}
	}

	u, err := h.users.Authenticate(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserInactive) {
			// Count every rejected credential pair the same way, including
			// unknown usernames. A best-effort failure here must not change the
			// response: the login is already invalid.
			if h.throttle != nil {
				if _, throttleErr := h.throttle.RecordFailure(r.Context(), username); throttleErr != nil {
					h.logger.Warn("login throttle record failure", "error", throttleErr)
				}
			}

			detail := "invalid credentials"
			if errors.Is(err, ErrUserInactive) {
				detail = "account inactive"
			}
			h.record(r, authlog.Event{
				Event:    authlog.EventLoginFailure,
				Outcome:  authlog.OutcomeFailure,
				Username: username,
				Detail:   detail,
			})
			h.renderLoginError(w, r, "Invalid username or password.", rd, username)
			return
		}
		h.logger.Error("authenticate user", "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventLoginFailure,
			Outcome:  authlog.OutcomeFailure,
			Username: username,
			Detail:   "internal error",
		})
		h.renderLoginError(w, r, "An error occurred. Please try again.", rd, username)
		return
	}

	// Correct password: clear any accumulated failures. Best-effort, like the
	// failure path — a store error must not fail a valid login.
	if h.throttle != nil {
		if err := h.throttle.Reset(r.Context(), username); err != nil {
			h.logger.Warn("login throttle reset", "error", err)
		}
	}

	// Resolve the return target first: an OAuth authorization request names the
	// app, and that app may override the session duration. See
	// appIDFromReturnTarget for which flows can and cannot know the app.
	dest, clearReturnCookie := h.resolveReturnDestination(r, u, rd)

	// ── Second factor ───────────────────────────────────────────────────────
	// Enforcement lives here, on the password flow only. Passkeys and magic
	// links deliberately do not get a second step: a WebAuthn assertion proves
	// possession of the authenticator itself, and a magic link proves control
	// of the mailbox. Do not add an MFA check to those paths.
	//
	// Note what has NOT happened yet: no session exists. The challenge below is
	// a separate table and a separate cookie that RequireSession never reads,
	// so a correct password alone can never yield a usable session for an
	// account with MFA enabled.
	if h.mfa != nil {
		enabled, mfaErr := h.mfa.Enabled(r.Context(), u.ID)
		if mfaErr != nil {
			// Fail closed: if we cannot tell whether the account has a second
			// factor, do not hand out a session that might skip it.
			h.logger.Error("mfa: check enrollment", "user_id", u.ID, "error", mfaErr)
			h.record(r, authlog.Event{
				Event:    authlog.EventLoginFailure,
				Outcome:  authlog.OutcomeFailure,
				UserID:   u.ID,
				Username: u.Username,
				Detail:   "mfa lookup failed",
			})
			h.renderLoginError(w, r, "An error occurred. Please try again.", rd, username)
			return
		}
		if enabled {
			h.startMFAChallenge(w, r, u, dest)
			return
		}
	}

	token, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, h.appIDFromReturnTarget(r.Context(), dest), r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("create session", "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventLoginFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "session create failed",
		})
		h.renderLoginError(w, r, "An error occurred. Please try again.", rd, username)
		return
	}

	setSessionCookie(w, token, expiresAt, h.cfg)
	h.record(r, authlog.Event{
		Event:    authlog.EventLoginSuccess,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   "password",
	})

	if clearReturnCookie {
		// Clear the passage_rd cookie now that we've consumed it.
		clearReturnCookieIfPresent(w, r, h.cfg)
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// GetLogout revokes the current session, clears the cookie, and redirects to /login.
func (h *Handler) GetLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.Session.EffectiveCookieName())
	if err == nil && cookie.Value != "" {
		outcome := authlog.OutcomeSuccess
		detail := ""
		if err := h.sessions.RevokeSession(r.Context(), cookie.Value); err != nil {
			// An already-expired or already-revoked session is routine, not a failure.
			if !strings.Contains(err.Error(), "not found") {
				h.logger.Warn("revoke session on logout", "error", err)
				outcome = authlog.OutcomeFailure
				detail = "session revoke failed"
			}
		}
		h.record(r, authlog.Event{
			Event:   authlog.EventLogout,
			Outcome: outcome,
			Detail:  detail,
		})
	}
	clearSessionCookie(w, h.cfg)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// renderLoginError is a convenience wrapper for re-rendering the login form with an error.
func (h *Handler) renderLoginError(w http.ResponseWriter, r *http.Request, msg, rd, username string) {
	h.render(w, r, "login.html", loginData{
		Flash:             &Flash{Type: "error", Message: msg},
		RedirectTo:        rd,
		Username:          username,
		AllowRegistration: h.registrationAllowed(r.Context()),
		AllowPassword:     isAuthMethodEnabled(r.Context(), h.settings, SettingPasswordEnabled),
		AllowPasskey:      isAuthMethodEnabled(r.Context(), h.settings, SettingPasskeyEnabled),
		AllowMagicLink:    isAuthMethodEnabled(r.Context(), h.settings, SettingMagicLinkEnabled),
		AllowProviders:    h.providerButtons(r.Context()),
		Tagline:           h.tagline(r.Context()),
		Wordmark:          h.wordmark(r.Context()),
		CSRFToken:         csrf.TokenFromContext(r.Context()),
	})
}
