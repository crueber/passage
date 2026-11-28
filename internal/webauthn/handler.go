package webauthn

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// userLookup is the minimal interface needed to look up users for WebAuthn ceremonies.
// Defined at the consumer boundary per Go convention.
type userLookup interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
	GetByUsername(ctx context.Context, username string) (*user.User, error)
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

// passkeyEnabled reads the passkey sign-in flag from live settings.
func (h *Handler) passkeyEnabled(ctx context.Context) bool {
	return settings.Bool(ctx, h.settings, settings.PasskeyEnabled, true)
}

// passwordEnabled reads the password sign-in policy from live settings.
func (h *Handler) passwordEnabled(ctx context.Context) bool {
	return settings.Bool(ctx, h.settings, settings.PasswordEnabled, true)
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
// When a rate limiter is supplied it wraps both endpoints so unauthenticated
// callers cannot flood webauthn_challenges or enumerate passkey usernames.
func (h *Handler) AuthRoutes(r chi.Router, limiters ...*ratelimit.Limiter) {
	if len(limiters) > 0 && limiters[0] != nil {
		mw := ratelimit.Middleware(limiters[0])
		r.With(mw).Post("/login/passkey/begin", h.GetBeginLogin)
		r.With(mw).Post("/login/passkey/finish", h.PostFinishLogin)
		return
	}
	r.Post("/login/passkey/begin", h.GetBeginLogin)
	r.Post("/login/passkey/finish", h.PostFinishLogin)
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

// render executes a named template, buffering output to avoid partial writes.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	web.Render(w, h.tmpl, h.logger, name, data)
}

// jsonError writes a JSON error response.
func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// dbCredsToWACreds converts our DB Credential slice to go-webauthn Credential slice
// by unmarshalling the stored JSON public key blob and restoring the persisted
// SignCount so authenticator clone detection compares against the latest count.
func dbCredsToWACreds(dbCreds []*Credential) ([]gowebauthn.Credential, error) {
	waCreds := make([]gowebauthn.Credential, 0, len(dbCreds))
	for _, dc := range dbCreds {
		var wc gowebauthn.Credential
		if err := json.Unmarshal(dc.PublicKey, &wc); err != nil {
			return nil, fmt.Errorf("unmarshal credential %s: %w", dc.ID, err)
		}
		wc.Authenticator.SignCount = dc.SignCount
		waCreds = append(waCreds, wc)
	}
	return waCreds, nil
}
