package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// userLookup is the minimal interface needed to look up users for WebAuthn ceremonies.
// Defined at the consumer boundary per Go convention.
type userLookup interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
}

// sessionCreator is the minimal interface for creating a session after passkey login.
// Defined at the consumer boundary per Go convention.
type sessionCreator interface {
	CreateSession(ctx context.Context, userID string, appID *string, ip, ua string) (token string, expiresAt time.Time, err error)
}

// Handler handles all WebAuthn/passkey HTTP endpoints.
type Handler struct {
	wa         *gowebauthn.WebAuthn
	credStore  CredentialStore
	challenges *ChallengeStore
	users      userLookup
	sessions   sessionCreator
	cfg        sessionConfig
	tmpl       *template.Template
	logger     *slog.Logger
}

// sessionConfig provides cookie configuration for setting the session after passkey login.
type sessionConfig struct {
	CookieName   string
	CookieSecure bool
}

// NewHandler creates a new WebAuthn Handler.
func NewHandler(
	wa *gowebauthn.WebAuthn,
	credStore CredentialStore,
	challenges *ChallengeStore,
	users userLookup,
	sessions sessionCreator,
	cookieName string,
	cookieSecure bool,
	tmpl *template.Template,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		wa:         wa,
		credStore:  credStore,
		challenges: challenges,
		users:      users,
		sessions:   sessions,
		cfg: sessionConfig{
			CookieName:   cookieName,
			CookieSecure: cookieSecure,
		},
		tmpl:   tmpl,
		logger: logger,
	}
}

// ProfileRoutes registers passkey management routes. The router must already have
// RequireSession middleware applied.
func (h *Handler) ProfileRoutes(r chi.Router) {
	r.Get("/passkeys", h.GetPasskeys)
	r.Post("/passkeys/delete/{id}", h.PostDeletePasskey)
	r.Get("/passkeys/register/begin", h.GetBeginRegistration)
	r.Post("/passkeys/register/finish", h.PostFinishRegistration)
}

// AuthRoutes registers the passkey login routes (public, no session required).
func (h *Handler) AuthRoutes(r chi.Router) {
	r.Get("/login/passkey/begin", h.GetBeginLogin)
	r.Post("/login/passkey/finish", h.PostFinishLogin)
}

// ─── passkeys page ───────────────────────────────────────────────────────────

type passkeysData struct {
	Credentials []*Credential
	Flash       *user.Flash
	CSRFToken   string
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
	}

	h.render(w, r, "passkeys.html", passkeysData{
		Credentials: creds,
		Flash:       flash,
		CSRFToken:   csrf.TokenFromContext(r.Context()),
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
		http.Redirect(w, r, "/passkeys", http.StatusFound)
		return
	}
	if cred.UserID != u.ID {
		h.logger.Warn("webauthn: credential ownership mismatch", "user_id", u.ID, "cred_user_id", cred.UserID)
		http.Redirect(w, r, "/passkeys?flash=error", http.StatusFound)
		return
	}

	if err := h.credStore.Delete(ctx, credID); err != nil {
		h.logger.Error("webauthn: delete credential", "id", credID, "error", err)
		http.Redirect(w, r, "/passkeys", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/passkeys?flash=deleted", http.StatusFound)
}

// ─── Registration ceremony ───────────────────────────────────────────────────

// GetBeginRegistration starts a passkey registration ceremony.
// Returns JSON with the credential creation options for the browser.
func (h *Handler) GetBeginRegistration(w http.ResponseWriter, r *http.Request) {
	u, ok := session.UserFromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Load existing credentials to exclude them (prevent re-registering same device).
	dbCreds, err := h.credStore.ListByUser(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("webauthn: list credentials for registration", "user_id", u.ID, "error", err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	waCreds, err := dbCredsToWACreds(dbCreds)
	if err != nil {
		h.logger.Error("webauthn: decode credentials for registration", "user_id", u.ID, "error", err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	waUser := NewWebAuthnUser(u, waCreds)

	options, sessionData, err := h.wa.BeginRegistration(waUser)
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

	dbCreds, err := h.credStore.ListByUser(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("webauthn: list credentials for finish registration", "user_id", u.ID, "error", err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	waCreds, err := dbCredsToWACreds(dbCreds)
	if err != nil {
		h.logger.Error("webauthn: decode credentials for finish registration", "user_id", u.ID, "error", err)
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	waUser := NewWebAuthnUser(u, waCreds)

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

	dbCred := &Credential{
		ID:        credIDStr,
		UserID:    u.ID,
		Name:      "",
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

// ─── Login ceremony ──────────────────────────────────────────────────────────

// GetBeginLogin starts a passkey login (discoverable credential) ceremony.
func (h *Handler) GetBeginLogin(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := h.wa.BeginDiscoverableLogin()
	if err != nil {
		h.logger.Error("webauthn: begin login", "error", err)
		jsonError(w, "failed to begin passkey login", http.StatusInternalServerError)
		return
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

// PostFinishLogin completes a passkey login ceremony.
func (h *Handler) PostFinishLogin(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("wa_auth_session")
	if err != nil {
		jsonError(w, "missing auth session", http.StatusBadRequest)
		return
	}

	sessionData, err := h.challenges.GetAuthentication(cookie.Value)
	if err != nil {
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

	waUser, credential, err := h.wa.FinishPasskeyLogin(handler, sessionData, r)
	if err != nil {
		h.logger.Warn("webauthn: finish login failed", "error", err)
		jsonError(w, "passkey authentication failed", http.StatusUnauthorized)
		return
	}

	// Reject potentially cloned authenticators.
	if credential.Authenticator.CloneWarning {
		h.logger.Warn("webauthn: possible cloned authenticator detected",
			"credential_id", base64.RawURLEncoding.EncodeToString(credential.ID))
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
	userID := string(waUser.WebAuthnID())
	ip := r.RemoteAddr
	ua := r.Header.Get("User-Agent")

	token, expiresAt, err := h.sessions.CreateSession(ctx, userID, nil, ip, ua)
	if err != nil {
		h.logger.Error("webauthn: create session after passkey login", "user_id", userID, "error", err)
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

	h.logger.Info("webauthn: passkey login succeeded", "user_id", userID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "redirect": "/"})
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// render executes a named template, buffering output to avoid partial writes.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.Error("webauthn: render template", "name", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// jsonError writes a JSON error response.
func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// dbCredsToWACreds converts our DB Credential slice to go-webauthn Credential slice
// by unmarshalling the stored JSON public key blob.
func dbCredsToWACreds(dbCreds []*Credential) ([]gowebauthn.Credential, error) {
	waCreds := make([]gowebauthn.Credential, 0, len(dbCreds))
	for _, dc := range dbCreds {
		var wc gowebauthn.Credential
		if err := json.Unmarshal(dc.PublicKey, &wc); err != nil {
			return nil, fmt.Errorf("unmarshal credential %s: %w", dc.ID, err)
		}
		waCreds = append(waCreds, wc)
	}
	return waCreds, nil
}
