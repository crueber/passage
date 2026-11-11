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
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// userLookup is the minimal interface needed to look up users for WebAuthn ceremonies.
// Defined at the consumer boundary per Go convention.
type userLookup interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
}

// webAuthnCeremony is the minimal interface for the WebAuthn library operations
// used by the Handler. Defined at the consumer boundary per Go convention.
type webAuthnCeremony interface {
	BeginRegistration(user gowebauthn.User, opts ...gowebauthn.RegistrationOption) (creation *protocol.CredentialCreation, session *gowebauthn.SessionData, err error)
	FinishRegistration(user gowebauthn.User, session gowebauthn.SessionData, r *http.Request) (credential *gowebauthn.Credential, err error)
	BeginLogin(user gowebauthn.User, opts ...gowebauthn.LoginOption) (assertion *protocol.CredentialAssertion, session *gowebauthn.SessionData, err error)
	FinishLogin(user gowebauthn.User, session gowebauthn.SessionData, r *http.Request) (credential *gowebauthn.Credential, err error)
	BeginDiscoverableLogin(opts ...gowebauthn.LoginOption) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error)
	FinishPasskeyLogin(handler gowebauthn.DiscoverableUserHandler, session gowebauthn.SessionData, r *http.Request) (gowebauthn.User, *gowebauthn.Credential, error)
}

// sessionCreator is the minimal interface for creating a session after passkey login.
// Defined at the consumer boundary per Go convention.
type sessionCreator interface {
	CreateSession(ctx context.Context, userID string, appID *string, ip, ua string) (token string, expiresAt time.Time, err error)
}

// passkeySettingsReader is the minimal interface for reading the passkey enable flag.
// Defined at the consumer boundary per Go convention.
type passkeySettingsReader interface {
	Get(ctx context.Context, key string) (string, error)
}

// mfaStatusReader reports the current user's second-factor state, so the
// Security page can render the TOTP section. Defined at the consumer boundary;
// backed by *mfa.Service in run.go.
type mfaStatusReader interface {
	Status(ctx context.Context, userID string) (mfa.Status, error)
}

// authEventRecorder records passkey authentication events for the admin
// security log. Defined at the consumer boundary; backed by *authlog.Recorder.
type authEventRecorder interface {
	Record(ctx context.Context, e authlog.Event)
}

// Handler handles all WebAuthn/passkey HTTP endpoints.
type Handler struct {
	wa         webAuthnCeremony
	credStore  CredentialStore
	challenges ChallengeStorer
	users      userLookup
	sessions   sessionCreator
	cfg        sessionConfig
	tmpl       *template.Template
	logger     *slog.Logger
	settings   passkeySettingsReader
	authEvents authEventRecorder
	mfa        mfaStatusReader
}

// sessionConfig provides cookie configuration for setting the session after passkey login.
type sessionConfig struct {
	CookieName   string
	CookieSecure bool
}

// NewHandler creates a new WebAuthn Handler.
func NewHandler(
	wa webAuthnCeremony,
	credStore CredentialStore,
	challenges ChallengeStorer,
	users userLookup,
	sessions sessionCreator,
	cookieName string,
	cookieSecure bool,
	tmpl *template.Template,
	logger *slog.Logger,
	settings passkeySettingsReader,
	authEvents authEventRecorder,
	mfaStatus mfaStatusReader,
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
		tmpl:       tmpl,
		logger:     logger,
		settings:   settings,
		authEvents: authEvents,
		mfa:        mfaStatus,
	}
}

// record emits an authentication event for r, filling in the client address
// and user agent. It is a no-op when no recorder is wired.
func (h *Handler) record(r *http.Request, e authlog.Event) {
	if h.authEvents == nil {
		return
	}
	e.IP = authlog.ClientIP(r)
	e.UserAgent = r.UserAgent()
	h.authEvents.Record(r.Context(), e)
}

// passkeyEnabled duplicates the isAuthMethodEnabled check for passkeys.
// This intentional duplication avoids a circular import: the webauthn package
// cannot import internal/user (which owns isAuthMethodEnabled) without a cycle.
// Fail-open: missing key or DB error → enabled.
func (h *Handler) passkeyEnabled(ctx context.Context) bool {
	if h.settings == nil {
		return true
	}
	val, err := h.settings.Get(ctx, "auth_passkey_enabled")
	if err != nil {
		return true
	}
	return strings.ToLower(strings.TrimSpace(val)) != "false"
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
	User        *user.User
	Credentials []*Credential
	Flash       *user.Flash
	CSRFToken   string

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

	h.render(w, r, "passkeys.html", passkeysData{
		User:              u,
		Credentials:       creds,
		Flash:             flash,
		CSRFToken:         csrf.TokenFromContext(r.Context()),
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

// ─── Login ceremony ──────────────────────────────────────────────────────────

// GetBeginLogin starts a passkey login (discoverable credential) ceremony.
func (h *Handler) GetBeginLogin(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyEnabled(r.Context()) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"passkey login is disabled"}`))
		return
	}

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

	waUser, credential, err := h.wa.FinishPasskeyLogin(handler, sessionData, r)
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

	h.logger.Info("webauthn: passkey login succeeded", "user_id", userID)
	h.record(r, authlog.Event{
		Event:    authlog.EventPasskeyLogin,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   userID,
		Username: username,
		Detail:   "passkey",
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "redirect": "/"})
}

// ─── Second-factor ceremony ──────────────────────────────────────────────────

// HasCredentials reports whether userID has at least one registered passkey.
// The second-factor page and the begin endpoint use it so the passkey option is
// only offered when it can actually complete a sign-in.
func (h *Handler) HasCredentials(ctx context.Context, userID string) (bool, error) {
	n, err := h.credStore.CountByUser(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("webauthn: count credentials: %w", err)
	}
	return n > 0, nil
}

// BeginSecondFactor starts an assertion ceremony for a user who has already
// proved their password, bound to the pending MFA challenge token bindKey.
//
// The allow-list is the user's own credentials rather than a discoverable
// login, and user verification is required: a second factor must prove the
// person at the authenticator, not merely possession of the device. The session
// data is stored under the challenge token, so the assertion can only complete
// the sign-in it was begun for.
func (h *Handler) BeginSecondFactor(ctx context.Context, u *user.User, bindKey string) ([]byte, error) {
	if bindKey == "" {
		return nil, fmt.Errorf("webauthn: begin second factor: empty challenge binding")
	}
	if !u.IsActive {
		return nil, fmt.Errorf("webauthn: begin second factor: account is inactive")
	}
	if !h.passkeyEnabled(ctx) {
		return nil, fmt.Errorf("webauthn: begin second factor: passkey login is disabled")
	}

	waCreds, err := h.userCredentials(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin second factor: %w", err)
	}
	if len(waCreds) == 0 {
		return nil, fmt.Errorf("webauthn: begin second factor: no credentials for the user")
	}

	options, sessionData, err := h.wa.BeginLogin(
		NewWebAuthnUser(u, waCreds),
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin second factor assertion: %w", err)
	}

	h.challenges.SetSecondFactor(bindKey, *sessionData)

	body, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("webauthn: marshal second factor options: %w", err)
	}
	return body, nil
}

// FinishSecondFactor verifies the assertion in r against the ceremony begun for
// bindKey and returns nil when it is valid.
//
// The ceremony data is single-use: it is popped before verification, so a
// failed or replayed assertion cannot be retried against the same options. The
// library additionally enforces that the asserted credential is on the allow
// list of the user passed here, that a returned user handle equals that user's
// ID, that the signed challenge is the one issued, and that the user-verified
// flag is set. Nothing here creates a session or touches the MFA challenge:
// completing the pending sign-in is the caller's job.
func (h *Handler) FinishSecondFactor(ctx context.Context, r *http.Request, u *user.User, bindKey string) error {
	if bindKey == "" {
		return fmt.Errorf("webauthn: finish second factor: empty challenge binding")
	}
	if !u.IsActive {
		return fmt.Errorf("webauthn: finish second factor: account is inactive")
	}
	if !h.passkeyEnabled(ctx) {
		return fmt.Errorf("webauthn: finish second factor: passkey login is disabled")
	}

	sessionData, err := h.challenges.GetSecondFactor(bindKey)
	if err != nil {
		return fmt.Errorf("webauthn: finish second factor ceremony: %w", err)
	}

	waCreds, err := h.userCredentials(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("webauthn: finish second factor: %w", err)
	}

	credential, err := h.wa.FinishLogin(NewWebAuthnUser(u, waCreds), sessionData, r)
	if err != nil {
		return fmt.Errorf("webauthn: verify second factor assertion: %w", err)
	}

	// Reject potentially cloned authenticators, exactly as passwordless login
	// does: a counter that went backwards is not evidence of the real device.
	if credential.Authenticator.CloneWarning {
		return fmt.Errorf("webauthn: verify second factor assertion: possible cloned authenticator")
	}

	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	if err := h.credStore.UpdateSignCount(ctx, credIDStr, credential.Authenticator.SignCount); err != nil {
		// Non-fatal: the assertion is already verified, and a stale counter only
		// weakens clone detection until the next successful use.
		h.logger.Warn("webauthn: update sign count after second factor", "credential_id", credIDStr, "error", err)
	}
	return nil
}

// userCredentials loads and decodes a user's stored passkeys for a ceremony.
func (h *Handler) userCredentials(ctx context.Context, userID string) ([]gowebauthn.Credential, error) {
	dbCreds, err := h.credStore.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	waCreds, err := dbCredsToWACreds(dbCreds)
	if err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	return waCreds, nil
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
