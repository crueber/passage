package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/session"
)

// GetBeginRegistration starts a passkey registration ceremony.
// Returns JSON with the credential creation options for the browser.
func (h *Handler) GetBeginRegistration(w http.ResponseWriter, r *http.Request) {
	u, ok := session.UserFromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Load existing credentials to exclude them (prevent re-registering same device).
	waCreds, err := h.userCredentials(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("webauthn: load credentials for registration", "user_id", u.ID, "error", err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	waUser := NewWebAuthnUser(u, waCreds)

	// The login page offers a username-less "Sign in with a passkey", which can
	// only find a *discoverable* (resident) credential. Without this selection
	// KeePassXC, Bitwarden and friends create an ordinary non-resident
	// credential: registration succeeds and the passkey can never be used.
	options, sessionData, err := h.wa.BeginRegistration(waUser,
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		h.logger.Error("webauthn: begin registration", "user_id", u.ID, "error", err)
		jsonError(w, "failed to begin registration", http.StatusInternalServerError)
		return
	}

	sessionID := sessionIDFromChallenge(sessionData.Challenge)
	h.challenges.SetRegistration(sessionID, *sessionData)

	// Return the session ID in a cookie so the finish handler can look it up.
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_reg_session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(challengeTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(options); err != nil {
		h.logger.Error("webauthn: encode registration options", "error", err)
	}
}

// PostFinishRegistration completes a passkey registration ceremony.
func (h *Handler) PostFinishRegistration(w http.ResponseWriter, r *http.Request) {
	u, ok := session.UserFromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cookie, err := r.Cookie("wa_reg_session")
	if err != nil {
		jsonError(w, "missing registration session", http.StatusBadRequest)
		return
	}

	sessionData, err := h.challenges.GetRegistration(cookie.Value)
	if err != nil {
		jsonError(w, "registration session expired or not found", http.StatusBadRequest)
		return
	}

	// Clear the session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_reg_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	waCreds, err := h.userCredentials(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("webauthn: load credentials for finish registration", "user_id", u.ID, "error", err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	waUser := NewWebAuthnUser(u, waCreds)

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	credential, err := h.wa.FinishRegistration(waUser, sessionData, r)
	if err != nil {
		h.logger.Warn("webauthn: finish registration failed", "user_id", u.ID, "error", err)
		jsonError(w, "registration failed", http.StatusBadRequest)
		return
	}

	// Encode credential ID as base64url for the DB primary key.
	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)

	// Persist the full credential as JSON.
	pubKeyJSON, err := json.Marshal(credential)
	if err != nil {
		h.logger.Error("webauthn: marshal credential", "error", err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	name := r.URL.Query().Get("name")
	if runes := []rune(name); len(runes) > 64 {
		name = string(runes[:64])
	}

	dbCred := &Credential{
		ID:        credIDStr,
		UserID:    u.ID,
		Name:      name,
		PublicKey: pubKeyJSON,
		SignCount: credential.Authenticator.SignCount,
	}

	if err := h.credStore.Create(r.Context(), dbCred); err != nil {
		h.logger.Error("webauthn: store credential", "user_id", u.ID, "error", err)
		jsonError(w, "failed to save passkey", http.StatusInternalServerError)
		return
	}

	h.logger.Info("webauthn: passkey registered", "user_id", u.ID, "credential_id", credIDStr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
