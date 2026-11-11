package idp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/user"
)

// Flow state lives in one short-lived HttpOnly cookie. It is provider-bound,
// compared in constant time, and cleared on every callback (single use).
const (
	stateCookieBase = "passage_oidc"
	stateTTL        = 10 * time.Minute
	flashFailure    = "idp-failed"
	flashNoAccount  = "idp-no-account"
	flashInactive   = "account-inactive"
)

// Errors that select a flash message without revealing provider internals.
var (
	errAccountInactive = errors.New("idp: linked account is inactive")
	errNoAccount       = errors.New("idp: no account for identity")
)

// sessionCreator is the session-creation interface, defined at the consumer
// boundary exactly as the user handler does (session imports user, so the
// reverse import would cycle).
type sessionCreator interface {
	CreateSession(ctx context.Context, userID string, appID *string, ip, ua string) (token string, expiresAt time.Time, err error)
}

// settingsReader reads the allow_registration policy setting.
type settingsReader interface {
	Get(ctx context.Context, key string) (string, error)
}

// appLister resolves the app named by an OAuth return target, so a sign-in
// started from /oauth/authorize gets that app's session duration.
type appLister interface {
	GetByClientID(ctx context.Context, clientID string) (*app.App, error)
}

// userService is the subset of *user.Service the flow needs. CreateExternalUser
// is on the consumer side because the policy gate lives here, not in the user
// package.
type userService interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
	GetByEmail(ctx context.Context, email string) (*user.User, error)
	CreateExternalUser(ctx context.Context, username, email, name string, emailVerified bool) (*user.User, error)
}

// authEventRecorder records authentication events. Best effort; may be nil.
type authEventRecorder interface {
	Record(ctx context.Context, e authlog.Event)
}

// Handler implements the start and callback legs of an upstream sign-in.
type Handler struct {
	links      LinkStore
	users      userService
	apps       appLister
	sessions   sessionCreator
	settings   settingsReader
	authEvents authEventRecorder
	client     *Client
	providers  map[string]*Provider
	cfg        *config.Config
	logger     *slog.Logger
	now        func() time.Time
}

// NewHandler wires the upstream sign-in flow. client may be nil, in which case
// a default HTTP client with a bounded timeout is used.
func NewHandler(
	links LinkStore,
	users userService,
	apps appLister,
	sessions sessionCreator,
	settings settingsReader,
	authEvents authEventRecorder,
	client *Client,
	cfg *config.Config,
	logger *slog.Logger,
) *Handler {
	if client == nil {
		client = NewClient(nil)
	}
	providers := make(map[string]*Provider)
	for _, p := range Providers(cfg.Auth.Providers) {
		providers[p.Name] = p
	}
	return &Handler{
		links:      links,
		users:      users,
		apps:       apps,
		sessions:   sessions,
		settings:   settings,
		authEvents: authEvents,
		client:     client,
		providers:  providers,
		cfg:        cfg,
		logger:     logger,
		now:        time.Now,
	}
}

// Routes registers the two public GET endpoints. Both are POST-free, so they
// run inside the anonymous route group without a CSRF token; the flow is bound
// by state, nonce, and PKCE instead.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/login/oidc/{provider}/start", h.Start)
	r.Get("/login/oidc/{provider}/callback", h.Callback)
}

// flowState is the cookie payload. It holds only request-binding values.
type flowState struct {
	Provider  string `json:"p"`
	State     string `json:"s"`
	Nonce     string `json:"n"`
	Verifier  string `json:"v"`
	ReturnTo  string `json:"r,omitempty"`
	ExpiresAt int64  `json:"e"`
}

// Start builds the authorization request and redirects the browser upstream.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	p, ok := h.provider(r)
	if !ok {
		h.failure(w, r, nil, nil, "unknown provider", flashFailure)
		return
	}

	rd := r.URL.Query().Get("rd")
	if !safeReturnPath(rd) {
		rd = ""
	}

	doc, err := h.client.Discover(r.Context(), p.Issuer)
	if err != nil {
		h.logger.Warn("idp start: discovery failed", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "discovery failed", flashFailure)
		return
	}

	state, err := randomToken(32)
	if err != nil {
		h.logger.Error("idp start: generate state", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "state generation failed", flashFailure)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		h.logger.Error("idp start: generate nonce", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "nonce generation failed", flashFailure)
		return
	}
	verifier, err := randomToken(32)
	if err != nil {
		h.logger.Error("idp start: generate verifier", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "verifier generation failed", flashFailure)
		return
	}

	payload, err := encodeFlowState(&flowState{
		Provider:  p.Name,
		State:     state,
		Nonce:     nonce,
		Verifier:  verifier,
		ReturnTo:  rd,
		ExpiresAt: h.now().Add(stateTTL).Unix(),
	})
	if err != nil {
		h.logger.Error("idp start: encode flow state", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "state encoding failed", flashFailure)
		return
	}
	h.setStateCookie(w, p.Name, payload)

	authURL, err := AuthCodeURL(doc, p, h.redirectURI(p.Name), state, nonce, PKCEChallenge(verifier))
	if err != nil {
		h.clearStateCookie(w, p.Name)
		h.logger.Error("idp start: build authorization URL", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "authorization URL failed", flashFailure)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback validates the flow, exchanges the code, verifies the id_token, and
// signs in (or links) the local account.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	p, ok := h.provider(r)
	if !ok {
		// No provider means no cookie name to scope to; any flow cookie left
		// over from an earlier attempt expires on its own.
		h.failure(w, r, nil, nil, "unknown provider", flashFailure)
		return
	}

	cookie, cookieErr := r.Cookie(h.stateCookieName(p.Name))
	// Single use: whatever happens, this flow state cannot be presented again.
	h.clearStateCookie(w, p.Name)

	if cookieErr != nil || cookie.Value == "" {
		h.failure(w, r, p, nil, "missing state cookie", flashFailure)
		return
	}
	st, err := decodeFlowState(cookie.Value)
	if err != nil {
		h.failure(w, r, p, nil, "invalid state cookie", flashFailure)
		return
	}
	if st.Provider != p.Name {
		h.failure(w, r, p, nil, "state cookie provider mismatch", flashFailure)
		return
	}
	if h.now().Unix() > st.ExpiresAt {
		h.failure(w, r, p, nil, "state cookie expired", flashFailure)
		return
	}

	gotState := r.URL.Query().Get("state")
	if gotState == "" || subtle.ConstantTimeCompare([]byte(gotState), []byte(st.State)) != 1 {
		h.failure(w, r, p, nil, "state mismatch", flashFailure)
		return
	}

	if providerErr := r.URL.Query().Get("error"); providerErr != "" {
		// The OAuth error code is a fixed vocabulary item; the description can
		// echo user or provider detail, so it is not recorded.
		h.failure(w, r, p, nil, "provider returned "+providerErr, flashFailure)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.failure(w, r, p, nil, "missing authorization code", flashFailure)
		return
	}

	doc, err := h.client.Discover(r.Context(), p.Issuer)
	if err != nil {
		h.logger.Warn("idp callback: discovery failed", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "discovery failed", flashFailure)
		return
	}

	idToken, err := h.client.Exchange(r.Context(), p, doc.TokenEndpoint, code, st.Verifier, h.redirectURI(p.Name))
	if err != nil {
		h.logger.Warn("idp callback: code exchange failed", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "code exchange failed", flashFailure)
		return
	}

	ident, err := h.client.VerifyIDToken(r.Context(), p, doc.JWKSURI, idToken, st.Nonce)
	if err != nil {
		h.logger.Warn("idp callback: id_token verification failed", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "id_token verification failed", flashFailure)
		return
	}

	u, err := h.resolveUser(r.Context(), p, ident)
	switch {
	case errors.Is(err, errAccountInactive):
		h.failure(w, r, p, nil, "account inactive", flashInactive)
		return
	case errors.Is(err, errNoAccount):
		h.failure(w, r, p, nil, "no linked account", flashNoAccount)
		return
	case err != nil:
		h.logger.Error("idp callback: link identity", "provider", p.Name, "error", err)
		h.failure(w, r, p, nil, "account linking failed", flashFailure)
		return
	}

	// No second factor here, deliberately. An external sign-in is a primary
	// method: the provider has already authenticated the user, and linking is
	// gated on a verified email or a pre-existing link. MFA enforcement lives
	// on the password flow only (Handler.PostLogin in the user package), the
	// same rule passkeys and magic links follow.
	token, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, h.appIDFromReturnTarget(r.Context(), st.ReturnTo), r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("idp callback: create session", "provider", p.Name, "user_id", u.ID, "error", err)
		h.failure(w, r, p, u, "session create failed", flashFailure)
		return
	}
	session.SetCookie(w, token, expiresAt, h.cfg)

	h.record(r, authlog.Event{
		Event:    authlog.EventIDPLogin,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   p.Name,
	})

	http.Redirect(w, r, returnDestination(st.ReturnTo, u), http.StatusFound)
}

// resolveUser applies the linking rules, in order:
//
//  1. an existing (provider, subject) link wins;
//  2. otherwise a user with the same verified email is linked;
//  3. otherwise a user is created when the provider sets auto_create and the
//     global registration policy allows it.
//
// An unverified email may never link to an existing account, but it can still
// create a new unverified account when auto_create is on. A linked or matched
// account must be active.
func (h *Handler) resolveUser(ctx context.Context, p *Provider, ident *Identity) (*user.User, error) {
	link, err := h.links.GetBySubject(ctx, p.Name, ident.Subject)
	switch {
	case err == nil:
		u, err := h.users.GetByID(ctx, link.UserID)
		if err != nil {
			return nil, fmt.Errorf("idp: load linked user: %w", err)
		}
		if !u.IsActive {
			return nil, errAccountInactive
		}
		return u, nil
	case !errors.Is(err, ErrLinkNotFound):
		return nil, fmt.Errorf("idp: look up link: %w", err)
	}

	if ident.Email != "" && ident.EmailVerified {
		u, err := h.users.GetByEmail(ctx, ident.Email)
		switch {
		case err == nil:
			if !u.IsActive {
				return nil, errAccountInactive
			}
			if err := h.linkUser(ctx, p, ident, u.ID); err != nil {
				return nil, err
			}
			return u, nil
		case !errors.Is(err, user.ErrNotFound):
			return nil, fmt.Errorf("idp: look up user by email: %w", err)
		}
	}

	if !p.AutoCreate || !h.registrationAllowed(ctx) {
		return nil, errNoAccount
	}

	u, err := h.users.CreateExternalUser(ctx, ident.PreferredUsername, ident.Email, ident.Name, ident.EmailVerified)
	if err != nil {
		// An email taken between the lookup and the insert is a refused link,
		// not an internal failure: never attach a second account to an address.
		if errors.Is(err, user.ErrEmailTaken) {
			return nil, errNoAccount
		}
		return nil, fmt.Errorf("idp: create user: %w", err)
	}
	if err := h.linkUser(ctx, p, ident, u.ID); err != nil {
		return nil, err
	}
	return u, nil
}

// linkUser records the (provider, subject) link. A concurrent callback that
// inserted the same pair first is not an error when it points at the same
// user; if it points elsewhere, the identity is contested and the sign-in is
// refused.
func (h *Handler) linkUser(ctx context.Context, p *Provider, ident *Identity, userID string) error {
	link := &Link{
		UserID:   userID,
		Provider: p.Name,
		Subject:  ident.Subject,
		Email:    ident.Email,
	}
	if err := h.links.Create(ctx, link); err != nil {
		if !errors.Is(err, ErrLinkExists) {
			return fmt.Errorf("idp: create link: %w", err)
		}
		existing, getErr := h.links.GetBySubject(ctx, p.Name, ident.Subject)
		if getErr != nil {
			return fmt.Errorf("idp: re-read created link: %w", getErr)
		}
		if existing.UserID != userID {
			return errors.New("idp: identity is already linked to a different user")
		}
	}
	return nil
}

// registrationAllowed mirrors the user handler: the stored policy decides, and
// the config snapshot is the fallback when the row is missing.
func (h *Handler) registrationAllowed(ctx context.Context) bool {
	return settings.Bool(ctx, h.settings, settings.AllowRegistration, h.cfg.Auth.AllowRegistration)
}

// provider resolves the {provider} route parameter against the configured set.
func (h *Handler) provider(r *http.Request) (*Provider, bool) {
	name := chi.URLParam(r, "provider")
	p, ok := h.providers[name]
	return p, ok
}

// redirectURI is the value registered with the provider. It must match the
// callback exactly, including the provider slug.
func (h *Handler) redirectURI(provider string) string {
	base := strings.TrimRight(h.cfg.Server.BaseURL, "/")
	return base + "/login/oidc/" + url.PathEscape(provider) + "/callback"
}

// appIDFromReturnTarget mirrors the password flow: only an OAuth authorization
// target names an app, and that app may override the session duration.
func (h *Handler) appIDFromReturnTarget(ctx context.Context, rd string) *string {
	if rd == "" {
		return nil
	}
	parsed, err := url.Parse(rd)
	if err != nil || parsed.Path != "/oauth/authorize" {
		return nil
	}
	clientID := parsed.Query().Get("client_id")
	if clientID == "" {
		return nil
	}
	a, err := h.apps.GetByClientID(ctx, clientID)
	if err != nil || a == nil {
		return nil
	}
	return &a.ID
}

// failure records idp.failure and sends the browser back to the login page
// with a flash. p and u may be nil. No token, code, or claim is ever recorded.
func (h *Handler) failure(w http.ResponseWriter, r *http.Request, p *Provider, u *user.User, reason, flash string) {
	e := authlog.Event{
		Event:   authlog.EventIDPFailure,
		Outcome: authlog.OutcomeFailure,
		Detail:  reason,
	}
	if p != nil {
		e.Detail = p.Name + ": " + reason
	}
	if u != nil {
		e.UserID = u.ID
		e.Username = u.Username
	}
	h.record(r, e)
	http.Redirect(w, r, "/login?flash="+url.QueryEscape(flash), http.StatusFound)
}

// record fills in the client address and user agent. No-op without a recorder.
func (h *Handler) record(r *http.Request, e authlog.Event) {
	if h.authEvents == nil {
		return
	}
	e.IP = authlog.ClientIP(r)
	e.UserAgent = r.UserAgent()
	h.authEvents.Record(r.Context(), e)
}

// stateCookieName scopes the flow cookie to one provider, applying the
// __Host- prefix when secure cookies are enabled (like the session and CSRF
// cookies). Two sign-ins started
// in different tabs (or with different providers) therefore do not overwrite
// each other's flow state, which would otherwise make the first callback fail
// with a state mismatch. Provider names are validated slugs, so they are safe
// in a cookie name.
func (h *Handler) stateCookieName(provider string) string {
	name := stateCookieBase + "_" + provider
	if h.cfg.Session.CookieSecure {
		return "__Host-" + name
	}
	return name
}

func (h *Handler) setStateCookie(w http.ResponseWriter, provider, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.stateCookieName(provider),
		Value:    value,
		Path:     "/",
		Expires:  h.now().Add(stateTTL),
		MaxAge:   int(stateTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearStateCookie(w http.ResponseWriter, provider string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.stateCookieName(provider),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func encodeFlowState(st *flowState) (string, error) {
	raw, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("encode flow state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeFlowState(value string) (*flowState, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode flow state: %w", err)
	}
	var st flowState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("decode flow state: %w", err)
	}
	return &st, nil
}

// randomToken returns n crypto/rand bytes as base64url without padding.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// safeReturnPath mirrors the user handler's open-redirect guard.
func safeReturnPath(rd string) bool {
	return rd != "" && strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//") && !strings.Contains(rd, "\\")
}

// returnDestination picks where a completed sign-in lands: the safe return
// target, then /admin for admins, then the dashboard.
func returnDestination(rd string, u *user.User) string {
	if safeReturnPath(rd) {
		return rd
	}
	if u != nil && u.IsAdmin {
		return "/admin"
	}
	return "/"
}
