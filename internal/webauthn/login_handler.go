package webauthn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/web"
)

// GetBeginLogin starts a passkey login (discoverable credential) ceremony.
func (h *Handler) GetBeginLogin(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyEnabled(r.Context()) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"passkey login is disabled"}`))
		return
	}

	// The body is optional. A username means "use that account's credentials"
	// (allowCredentials), which works with a credential that is not discoverable
	// — including every passkey created before registration required resident
	// keys. No username means the original discoverable/username-less ceremony.
	var req struct {
		Username string `json:"username"`
	}
	if r.Body != nil {
		// A malformed or empty body is not an error: fall back to discoverable.
		_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req)
	}
	username := strings.TrimSpace(req.Username)

	var options *protocol.CredentialAssertion
	var sessionData *gowebauthn.SessionData
	var err error

	if username != "" {
		options, sessionData, err = h.beginForUsername(r.Context(), username)
		if err != nil {
			// Same answer for an unknown account and an account without
			// credentials, so the endpoint is not a membership oracle.
			jsonError(w, "No passkey is registered for that account.", http.StatusBadRequest)
			return
		}
	} else {
		options, sessionData, err = h.wa.BeginDiscoverableLogin(
			gowebauthn.WithUserVerification(protocol.VerificationPreferred),
		)
		if err != nil {
			h.logger.Error("webauthn: begin login", "error", err)
			jsonError(w, "failed to begin passkey login", http.StatusInternalServerError)
			return
		}
	}

	sessionID := sessionIDFromChallenge(sessionData.Challenge)
	h.challenges.SetAuthentication(sessionID, *sessionData)

	http.SetCookie(w, &http.Cookie{
		Name:     "wa_auth_session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(challengeTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(options); err != nil {
		h.logger.Error("webauthn: encode login options", "error", err)
	}
}

// beginForUsername starts a user-bound assertion ceremony: the credentials are
// sent as allowCredentials, so the authenticator does not have to hold a
// discoverable credential.
func (h *Handler) beginForUsername(ctx context.Context, username string) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	u, err := h.users.GetByUsername(ctx, username)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup user: %w", err)
	}
	if !u.IsActive {
		return nil, nil, fmt.Errorf("user account is inactive")
	}

	dbCreds, err := h.credStore.ListByUser(ctx, u.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("list credentials: %w", err)
	}
	if len(dbCreds) == 0 {
		return nil, nil, fmt.Errorf("no credentials")
	}

	waCreds, err := dbCredsToWACreds(dbCreds)
	if err != nil {
		return nil, nil, fmt.Errorf("decode credentials: %w", err)
	}

	waUser := NewWebAuthnUser(u, waCreds)
	return h.wa.BeginLogin(waUser, gowebauthn.WithUserVerification(protocol.VerificationPreferred))
}

// PostFinishLogin completes a passkey login ceremony.
func (h *Handler) PostFinishLogin(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyEnabled(r.Context()) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"passkey login is disabled"}`))
		return
	}

	cookie, err := r.Cookie("wa_auth_session")
	if err != nil {
		jsonError(w, "missing auth session", http.StatusBadRequest)
		return
	}

	sessionData, err := h.challenges.GetAuthentication(cookie.Value)
	if err != nil {
		h.record(r, authlog.Event{
			Event:   authlog.EventPasskeyFailure,
			Outcome: authlog.OutcomeFailure,
			Detail:  "challenge expired or not found",
		})
		jsonError(w, "auth session expired or not found", http.StatusBadRequest)
		return
	}

	// Clear the auth session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_auth_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	ctx := r.Context()

	// DiscoverableUserHandler: given the credential's rawID and userHandle,
	// load the user and their credentials from our database.
	handler := func(rawID, userHandle []byte) (gowebauthn.User, error) {
		userID := string(userHandle)
		u, err := h.users.GetByID(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("user lookup: %w", err)
		}
		// Check the user is active before allowing passkey authentication.
		if !u.IsActive {
			return nil, fmt.Errorf("user account is inactive")
		}

		dbCreds, err := h.credStore.ListByUser(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("list credentials: %w", err)
		}

		waCreds, err := dbCredsToWACreds(dbCreds)
		if err != nil {
			return nil, fmt.Errorf("decode credentials: %w", err)
		}

		return NewWebAuthnUser(u, waCreds), nil
	}

	// A session started with a username carries that user's ID in the session
	// data; finish it as a user-bound ceremony (allowCredentials). Otherwise it
	// was the discoverable ceremony and the authenticator tells us who it is.
	var waUser gowebauthn.User
	var credential *gowebauthn.Credential
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if len(sessionData.UserID) > 0 {
		u, uerr := h.users.GetByID(ctx, string(sessionData.UserID))
		if uerr != nil {
			h.logger.Warn("webauthn: finish login user lookup failed", "error", uerr)
			h.record(r, authlog.Event{
				Event:   authlog.EventPasskeyFailure,
				Outcome: authlog.OutcomeFailure,
				Detail:  "user lookup failed",
			})
			jsonError(w, "passkey authentication failed", http.StatusUnauthorized)
			return
		}
		if !u.IsActive {
			h.logger.Warn("webauthn: finish login for inactive user", "user_id", u.ID)
			h.record(r, authlog.Event{
				Event:    authlog.EventPasskeyFailure,
				Outcome:  authlog.OutcomeFailure,
				UserID:   u.ID,
				Username: u.Username,
				Detail:   "account inactive",
			})
			jsonError(w, "passkey authentication failed", http.StatusUnauthorized)
			return
		}
		waCreds, cerr := h.userCredentials(ctx, u.ID)
		if cerr != nil {
			h.logger.Error("webauthn: load credentials for finish", "user_id", u.ID, "error", cerr)
			h.record(r, authlog.Event{
				Event:    authlog.EventPasskeyFailure,
				Outcome:  authlog.OutcomeFailure,
				UserID:   u.ID,
				Username: u.Username,
				Detail:   "credential load failed",
			})
			jsonError(w, "passkey authentication failed", http.StatusInternalServerError)
			return
		}
		waUser = NewWebAuthnUser(u, waCreds)
		credential, err = h.wa.FinishLogin(waUser, sessionData, r)
	} else {
		waUser, credential, err = h.wa.FinishPasskeyLogin(handler, sessionData, r)
	}
	if err != nil {
		h.logger.Warn("webauthn: finish login failed", "error", err)
		e := authlog.Event{
			Event:   authlog.EventPasskeyFailure,
			Outcome: authlog.OutcomeFailure,
			Detail:  "authentication failed",
		}
		if waUser != nil {
			e.UserID = string(waUser.WebAuthnID())
			e.Username = waUser.WebAuthnName()
		}
		h.record(r, e)
		jsonError(w, "passkey authentication failed", http.StatusUnauthorized)
		return
	}

	// Reject potentially cloned authenticators.
	if credential.Authenticator.CloneWarning {
		h.logger.Warn("webauthn: possible cloned authenticator detected",
			"credential_id", base64.RawURLEncoding.EncodeToString(credential.ID))
		h.record(r, authlog.Event{
			Event:    authlog.EventPasskeyFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   string(waUser.WebAuthnID()),
			Username: waUser.WebAuthnName(),
			Detail:   "possible cloned authenticator",
		})
		jsonError(w, "passkey authentication failed", http.StatusUnauthorized)
		return
	}

	// Update the sign count in the database.
	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	if err := h.credStore.UpdateSignCount(ctx, credIDStr, credential.Authenticator.SignCount); err != nil {
		// Non-fatal: log and continue.
		h.logger.Warn("webauthn: update sign count", "credential_id", credIDStr, "error", err)
	}

	// Create a Passage session for the authenticated user.
	//
	// No second factor is requested here, deliberately: a WebAuthn assertion
	// already proves possession of the authenticator, so a passkey sign-in is
	// itself two factors (device + gesture/biometric). MFA enforcement lives in
	// user.Handler.PostLogin, on the password flow only.
	//
	// appID is always nil here: this endpoint is a JSON call from the login
	// page and receives no return target, so the app the user came from is
	// unknowable. The session therefore gets the global duration. Flows that
	// can name an app resolve it in user.Handler.appIDFromReturnTarget.
	userID := string(waUser.WebAuthnID())
	username := waUser.WebAuthnName()
	ip := r.RemoteAddr
	ua := r.Header.Get("User-Agent")

	token, expiresAt, err := h.sessions.CreateSession(ctx, userID, nil, ip, ua)
	if err != nil {
		h.logger.Error("webauthn: create session after passkey login", "user_id", userID, "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventPasskeyFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   userID,
			Username: username,
			Detail:   "session create failed",
		})
		jsonError(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	dest := "/"
	if rdVal, ok := web.ReadReturnCookie(r); ok && web.SafeReturnPath(rdVal) {
		dest = rdVal
		web.ClearReturnCookie(w, r, h.cfg.CookieSecure)
	} else if u, uerr := h.users.GetByID(ctx, userID); uerr == nil && u != nil && u.IsAdmin {
		dest = "/admin"
	}

	h.logger.Info("webauthn: passkey login succeeded", "user_id", userID)
	h.record(r, authlog.Event{
		Event:    authlog.EventPasskeyLogin,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   userID,
		Username: username,
		Detail:   "passkey",
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "redirect": dest})
}
