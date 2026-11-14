package user

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/mfa"
)

// secondFactorPasskey is the WebAuthn bridge for the pending second-factor
// challenge. The HTTP flow lives in this package; the ceremony lives in
// internal/webauthn, which already imports this package, so the interface is
// declared here at the consumer boundary and implemented by *webauthn.Handler
// (wired in run.go). A nil implementation means "no passkey option", which is
// what tests and a deployment with passkeys disabled see.
//
// Nothing in this interface creates a session. A verified assertion is only a
// verified factor; completeMFAChallenge turns it into a session through the
// same path a TOTP code takes.
type secondFactorPasskey interface {
	// HasCredentials reports whether the user has at least one passkey, so the
	// second-factor page and the begin endpoint only offer the option when it
	// can work.
	HasCredentials(ctx context.Context, userID string) (bool, error)
	// BeginSecondFactor starts an assertion ceremony bound to bindKey (the
	// pending challenge token) and returns the request options as JSON.
	BeginSecondFactor(ctx context.Context, u *User, bindKey string) ([]byte, error)
	// FinishSecondFactor verifies the assertion in r against the ceremony begun
	// for bindKey.
	FinishSecondFactor(ctx context.Context, r *http.Request, u *User, bindKey string) error
}

// SetSecondFactorPasskey wires the passkey second factor. It is a setter rather
// than a constructor argument because run.go builds the WebAuthn handler after
// this one; a nil bridge leaves the feature off.
func (h *Handler) SetSecondFactorPasskey(p secondFactorPasskey) {
	h.passkey = p
}

// passkeySecondFactorEnabled reports whether a passkey may be used at all: the
// bridge is wired and passkeys are enabled by policy. Fail-open on the settings
// read, like every other auth-method flag.
func (h *Handler) passkeySecondFactorEnabled(ctx context.Context) bool {
	return h.passkey != nil && isAuthMethodEnabled(ctx, h.settings, SettingPasskeyEnabled)
}

// passkeySecondFactorAvailable reports whether a passkey can complete a pending
// challenge for userID right now. The decision is made server-side so the page
// never offers a button that cannot work.
func (h *Handler) passkeySecondFactorAvailable(ctx context.Context, userID string) bool {
	if !h.passkeySecondFactorEnabled(ctx) {
		return false
	}
	has, err := h.passkey.HasCredentials(ctx, userID)
	if err != nil {
		// A credential-store problem hides the option rather than breaking the
		// page: a TOTP code or a recovery code still works.
		h.logger.Warn("mfa: check passkey credentials", "user_id", userID, "error", err)
		return false
	}
	return has
}

// PostMFAPasskeyBegin starts a WebAuthn assertion for the pending second-factor
// challenge. The assertion is bound to the challenge token, so it can only
// complete this sign-in.
//
// JSON API, no CSRF token: like the passwordless passkey endpoints, it is
// driven by passkey.js and authenticated by the SameSite=Lax pending cookie,
// which is HttpOnly and cannot be read or forged cross-site.
func (h *Handler) PostMFAPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	ch, u, ok := h.passkeyChallenge(w, r)
	if !ok {
		return
	}
	if !h.passkeySecondFactorAvailable(r.Context(), u.ID) {
		// No bridge, passkeys disabled, or no credential: a caller that asks
		// anyway gets the same answer the page acts on.
		h.jsonError(w, "passkey sign-in is not available", http.StatusNotFound)
		return
	}

	options, err := h.passkey.BeginSecondFactor(r.Context(), u, ch.Token)
	if err != nil {
		h.logger.Error("mfa: begin passkey second factor", "user_id", u.ID, "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventMFAFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "passkey ceremony failed to start",
		})
		h.jsonError(w, "failed to start passkey sign-in", http.StatusInternalServerError)
		return
	}

	h.jsonOK(w, options)
}

// PostMFAPasskeyFinish verifies a passkey assertion and, only then, completes
// the pending challenge exactly like a verified code.
func (h *Handler) PostMFAPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	ch, u, ok := h.passkeyChallenge(w, r)
	if !ok {
		return
	}
	if !h.passkeySecondFactorEnabled(r.Context()) {
		h.jsonError(w, "passkey sign-in is not available", http.StatusNotFound)
		return
	}

	if err := h.passkey.FinishSecondFactor(r.Context(), r, u, ch.Token); err != nil {
		// Never echo the assertion or the library error to the client: a wrong
		// signature, an expired ceremony, and a replayed one are one answer.
		// The challenge stays live, so a code (or a fresh passkey attempt)
		// still completes the sign-in.
		h.logger.Warn("mfa: passkey second factor failed", "user_id", u.ID, "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventMFAFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "passkey assertion failed",
		})
		h.jsonError(w, "passkey authentication failed", http.StatusUnauthorized)
		return
	}

	dest, err := h.completeMFAChallenge(w, r, ch, u, "passkey")
	if err != nil {
		// completeMFAChallenge has already logged and recorded the failure. The
		// JSON caller only needs a generic answer; the challenge is consumed
		// unless the failure happened before that point, so the browser must
		// start sign-in again.
		h.jsonError(w, "an error occurred. please sign in again.", http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(map[string]string{"redirect": dest})
	if err != nil {
		h.logger.Error("mfa: marshal passkey redirect", "error", err)
		h.jsonError(w, "an error occurred. please sign in again.", http.StatusInternalServerError)
		return
	}
	h.jsonOK(w, body)
}

// passkeyChallenge loads the pending challenge for a JSON passkey call. Every
// "no usable challenge" case — missing cookie, expired row, vanished or
// deactivated account — is answered the same way, so the endpoint reveals
// nothing about the token it was given.
func (h *Handler) passkeyChallenge(w http.ResponseWriter, r *http.Request) (*mfa.Challenge, *User, bool) {
	ch, u, err := h.mfaChallengeUser(r)
	if err != nil {
		clearMFACookie(w, h.cfg)
		if errors.Is(err, errMFALoadUser) {
			h.jsonError(w, "an error occurred. please try again.", http.StatusInternalServerError)
		} else {
			h.jsonError(w, "your sign-in has expired. please start again.", http.StatusForbidden)
		}
		return nil, nil, false
	}
	return ch, u, true
}

// jsonError writes a JSON error. The header has to be sent before the body, so
// an encode failure of these fixed messages can only be logged.
func (h *Handler) jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		h.logger.Warn("mfa: write json error", "error", err)
	}
}

// jsonOK writes a 200 with an already-marshalled JSON body. The WebAuthn
// options are produced as JSON by the ceremony, so they must not be re-encoded
// into a JSON string.
func (h *Handler) jsonOK(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		h.logger.Warn("mfa: write json body", "error", err)
	}
}
