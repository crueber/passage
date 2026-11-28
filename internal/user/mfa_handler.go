package user

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/mfa"
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
			if derr := h.mfa.ConsumeChallenge(r.Context(), cookie.Value); derr != nil && !errors.Is(derr, mfa.ErrNotFound) {
				h.logger.Warn("mfa: delete expired challenge", "error", derr)
			}
		}
		return nil, false
	}
	return ch, true
}

// Errors returned by mfaChallengeUser. They exist so each caller can answer in
// its own style — an HTML redirect on the code form, a JSON error on the
// passkey API — without repeating the lookup and its logging.
var (
	errMFANoChallenge     = errors.New("mfa: no live challenge")
	errMFALoadUser        = errors.New("mfa: load challenge user")
	errMFAAccountInactive = errors.New("mfa: challenge account is inactive")
)

// Errors returned by completeMFAChallenge. The consume failure is distinct
// because the pending challenge survives it; every other failure happens after
// the challenge is gone.
var errMFAConsumeChallenge = errors.New("mfa: consume challenge")

// mfaChallengeUser loads the live challenge named by the pending cookie and the
// account it belongs to, refusing an account that was deactivated between the
// password and the second factor: a challenge must not outlive the account.
func (h *Handler) mfaChallengeUser(r *http.Request) (*mfa.Challenge, *User, error) {
	ch, ok := h.liveChallenge(r)
	if !ok {
		return nil, nil, errMFANoChallenge
	}
	u, err := h.users.GetByID(r.Context(), ch.UserID)
	if err != nil {
		h.logger.Error("mfa: load user for challenge", "user_id", ch.UserID, "error", err)
		return nil, nil, fmt.Errorf("%w: %w", errMFALoadUser, err)
	}
	if !u.IsActive {
		h.record(r, authlog.Event{
			Event:    authlog.EventMFAFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "account inactive",
		})
		return nil, nil, errMFAAccountInactive
	}
	return ch, u, nil
}

// completeMFAChallenge is the one path from "second factor verified" to
// "signed in", shared by the code form (PostMFALogin) and the passkey assertion
// (PostMFAPasskeyFinish): consume the challenge, create the session for the app
// named by the return target, set the session cookie, clear the pending
// cookies, record mfa.success with method, and return the same-site redirect
// target.
//
// It writes the session cookie itself; the caller only redirects. A failure is
// returned (already logged and recorded) so each caller can answer in its own
// style, and no session exists unless the challenge was consumed first.
func (h *Handler) completeMFAChallenge(w http.ResponseWriter, r *http.Request, ch *mfa.Challenge, u *User, method string) (string, error) {
	// The challenge grants exactly one session. Deleting it is part of the
	// verification, not cleanup: if it cannot be deleted, no session is created
	// (the factor itself is still single-use, but the pending password proof
	// must not survive a completed sign-in).
	if err := h.mfa.ConsumeChallenge(r.Context(), ch.Token); err != nil {
		h.logger.Error("mfa: consume challenge", "user_id", u.ID, "error", err)
		return "", fmt.Errorf("%w: %w", errMFAConsumeChallenge, err)
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
		return "", fmt.Errorf("create session: %w", err)
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
	return dest, nil
}
