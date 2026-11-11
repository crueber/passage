package oauth

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
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
	"github.com/crueber/passage/internal/user"
)

// oauthService is the interface the Handler uses for OAuth operations.
// Defined here at the consumer boundary, per Go convention.
type oauthService interface {
	Authorize(ctx context.Context, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string, sessionCreatedAt time.Time, userID, clientIP string) (*Code, error)
	ExchangeCode(ctx context.Context, code, clientID, clientSecret, redirectURI, codeVerifier string) (*TokenResponse, error)
	RefreshTokens(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenResponse, error)
	ValidateAccessToken(ctx context.Context, token string) (*user.User, *Token, error)
	// TokenAssignments resolves a user's app-scoped role names and effective
	// (direct plus role-inherited) group names for the userinfo response.
	TokenAssignments(ctx context.Context, userID, appID string) (roles, groups []string, err error)
	// ClientForIDTokenHint verifies an id_token presented as a logout hint and
	// returns the app it was issued to.
	ClientForIDTokenHint(ctx context.Context, idTokenHint string) (*app.App, error)
	// RevokeToken implements RFC 7009 revocation.
	RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error
	// IntrospectToken implements RFC 7662 introspection. A nil result means
	// the token is not active.
	IntrospectToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*TokenInfo, error)
	// ActiveSigningKeys returns the non-retired keys to publish in the JWKS.
	ActiveSigningKeys() []*SigningKey
}

// sessionValidator is the interface the Handler uses to validate and revoke
// browser sessions.
// Defined here at the consumer boundary, per Go convention.
type sessionValidator interface {
	ValidateSession(ctx context.Context, token string) (*session.Session, *user.User, error)
	RevokeSession(ctx context.Context, token string) error
}

// authEventRecorder records authentication events for the admin security log.
// Defined at the consumer boundary; backed by *authlog.Recorder in run.go.
// Recording is best-effort: the Recorder never returns an error.
type authEventRecorder interface {
	Record(ctx context.Context, e authlog.Event)
}

// Handler handles OAuth2/OIDC HTTP requests.
type Handler struct {
	svc        oauthService
	sessions   sessionValidator
	baseURL    string
	authEvents authEventRecorder
	cfg        *config.Config
	logger     *slog.Logger
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(svc oauthService, sessions sessionValidator, baseURL string, authEvents authEventRecorder, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		svc:        svc,
		sessions:   sessions,
		baseURL:    baseURL,
		authEvents: authEvents,
		cfg:        cfg,
		logger:     logger,
	}
}

// record emits an authentication event for r, filling in the client address
// and user agent. It is a no-op when no recorder is wired (unit tests).
func (h *Handler) record(r *http.Request, e authlog.Event) {
	if h.authEvents == nil {
		return
	}
	e.IP = authlog.ClientIP(r)
	e.UserAgent = r.UserAgent()
	h.authEvents.Record(r.Context(), e)
}

// Routes registers the OAuth2/OIDC routes on the given router.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.Discovery)
	r.Get("/.well-known/jwks.json", h.JWKS)
	r.Get("/oauth/authorize", h.Authorize)
	r.Post("/oauth/token", h.Token)
	r.Get("/oauth/userinfo", h.UserInfo)
	r.Get("/oauth/logout", h.Logout)
	r.Post("/oauth/logout", h.Logout)
	r.Post("/oauth/revoke", h.Revoke)
	r.Post("/oauth/introspect", h.Introspect)
}

// Discovery returns the OpenID Connect discovery document.
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                        h.baseURL,
		"authorization_endpoint":                        h.baseURL + "/oauth/authorize",
		"token_endpoint":                                h.baseURL + "/oauth/token",
		"userinfo_endpoint":                             h.baseURL + "/oauth/userinfo",
		"end_session_endpoint":                          h.baseURL + "/oauth/logout",
		"revocation_endpoint":                           h.baseURL + "/oauth/revoke",
		"introspection_endpoint":                        h.baseURL + "/oauth/introspect",
		"jwks_uri":                                      h.baseURL + "/.well-known/jwks.json",
		"response_types_supported":                      []string{"code"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"scopes_supported":                              []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_post", "client_secret_basic"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token"},
		"claims_supported":                              []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "email_verified", "preferred_username", "roles", "groups"},
		"nonce_supported":                               true,
		"code_challenge_methods_supported":              []string{"S256"},
	}

	h.writeJSON(w, http.StatusOK, doc)
}

// JWKS returns the JSON Web Key Set of every non-retired signing key. Each key
// carries its own kid, so a client can verify an id_token signed before a
// rotation by selecting the matching entry.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	keys := h.svc.ActiveSigningKeys()
	if len(keys) == 0 {
		// Startup guarantees at least one key and the last key cannot be
		// retired, so this is a broken invariant, not a normal state.
		h.logger.Error("oauth: JWKS requested with no active signing key")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	jwks := map[string]any{
		"keys": jwksFor(keys),
	}

	h.writeJSON(w, http.StatusOK, jwks)
}

// jwksFor renders signing keys as RFC 7517 JWK entries.
func jwksFor(keys []*SigningKey) []map[string]any {
	jwks := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		pub := key.PublicKey()
		if pub == nil {
			continue
		}

		// Encode the modulus (n) as base64url with no padding.
		nEncoded := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())

		// Encode the exponent (e) as big-endian bytes then base64url.
		// e is typically 65537 (0x010001), which fits in 3 bytes.
		eBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(eBuf, uint32(pub.E)) //nolint:gosec // e fits in uint32
		// Trim leading zero bytes.
		i := 0
		for i < len(eBuf)-1 && eBuf[i] == 0 {
			i++
		}
		eEncoded := base64.RawURLEncoding.EncodeToString(eBuf[i:])

		jwks = append(jwks, map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": key.KID,
			"n":   nEncoded,
			"e":   eEncoded,
		})
	}
	return jwks
}

// Authorize handles the OAuth2 authorization endpoint.
// If no valid session is present, it redirects to the login page.
// On success, it redirects to the redirect_uri with the authorization code.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	// Validate required parameters.
	if responseType != "code" {
		h.writeJSONError(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be \"code\"")
		return
	}
	if clientID == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	if redirectURI == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}

	// Validate the session.
	cookie, err := r.Cookie(h.cfg.Session.EffectiveCookieName())
	if err != nil {
		// No session cookie — redirect to login.
		h.redirectToLogin(w, r)
		return
	}

	sess, u, err := h.sessions.ValidateSession(ctx, cookie.Value)
	if err != nil {
		h.redirectToLogin(w, r)
		return
	}

	// Attempt to authorize.
	code, err := h.svc.Authorize(ctx, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, sess.CreatedAt, u.ID, authlog.ClientIP(r))
	if err != nil {
		h.record(r, authlog.Event{
			Event:    authlog.EventOAuthAuthorize,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   authorizeDenyReason(err) + " client_id=" + clientID,
		})
		var denial *PolicyDenialError
		switch {
		case errors.As(err, &denial):
			// The app's access policy refused the user. The specific rule is
			// recorded in the auth event and the log, never in the response:
			// OAuth clients get the same fixed description as any other
			// authorization denial.
			h.logger.Info("oauth authorize: access policy denied",
				"user_id", u.ID, "username", u.Username, "app_slug", denial.AppSlug, "reason", denial.Reason)
			h.record(r, authlog.Event{
				Event:    authlog.EventAccessDenied,
				Outcome:  authlog.OutcomeFailure,
				UserID:   u.ID,
				Username: u.Username,
				Detail:   "app=" + denial.AppSlug + " reason=" + denial.Reason,
			})
			h.writeJSONError(w, http.StatusForbidden, "access_denied",
				"The resource owner or authorization server denied the request.")
		case errors.Is(err, app.ErrOAuthNotEnabled):
			h.writeJSONError(w, http.StatusBadRequest, "unauthorized_client",
				"OAuth is not enabled for this client")
		case errors.Is(err, app.ErrRedirectURIMismatch):
			h.writeJSONError(w, http.StatusBadRequest, "invalid_request",
				"redirect_uri does not match registered URIs")
		case errors.Is(err, ErrPKCEVerificationFailed):
			h.writeJSONError(w, http.StatusBadRequest, "invalid_request",
				"invalid code_challenge or code_challenge_method")
		default:
			// Fixed description: err may wrap internal details (DB errors,
			// store chains) that must not reach the client. Log the real error.
			h.logger.Warn("oauth authorize: access denied", "user_id", u.ID, "error", err)
			h.writeJSONError(w, http.StatusForbidden, "access_denied",
				"The resource owner or authorization server denied the request.")
		}
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventOAuthAuthorize,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   "client_id=" + clientID,
	})

	// Redirect to the redirect_uri with the authorization code.
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is malformed")
		return
	}
	qp := redirectURL.Query()
	qp.Set("code", code.Code)
	if state != "" {
		qp.Set("state", state)
	}
	redirectURL.RawQuery = qp.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// Token handles the OAuth2 token endpoint.
// Supports authorization_code and refresh_token grant types.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// RFC 6749 §5.1: token responses must not be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body")
		return
	}

	// Parse client credentials: Basic auth takes priority over form body.
	clientID, clientSecret := extractClientCredentials(r)
	if clientID == "" {
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client credentials are required")
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthCodeGrant(ctx, w, r, clientID, clientSecret)
	case "refresh_token":
		h.handleRefreshTokenGrant(ctx, w, r, clientID, clientSecret)
	default:
		h.writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

// handleAuthCodeGrant processes the authorization_code grant type.
func (h *Handler) handleAuthCodeGrant(ctx context.Context, w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	if redirectURI == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}

	resp, err := h.svc.ExchangeCode(ctx, code, clientID, clientSecret, redirectURI, codeVerifier)
	if err != nil {
		h.record(r, authlog.Event{
			Event:   authlog.EventOAuthTokenFailed,
			Outcome: authlog.OutcomeFailure,
			Detail:  "authorization_code",
		})
		h.writeTokenError(w, err)
		return
	}

	h.record(r, authlog.Event{
		Event:   authlog.EventOAuthToken,
		Outcome: authlog.OutcomeSuccess,
		Detail:  "authorization_code",
	})
	h.writeJSON(w, http.StatusOK, resp)
}

// handleRefreshTokenGrant processes the refresh_token grant type.
func (h *Handler) handleRefreshTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	resp, err := h.svc.RefreshTokens(ctx, refreshToken, clientID, clientSecret)
	if err != nil {
		// Refresh-token reuse is a security event, not an ordinary bad grant.
		// Log it here (no token material) — the integrator hooks authentication
		// event emission onto this branch, and the service has already revoked
		// the whole family by the time the error is returned.
		var reuseErr *RefreshTokenReuseError
		if errors.As(err, &reuseErr) {
			h.logger.Warn("oauth refresh token reuse detected; token family revoked",
				"app_id", reuseErr.AppID,
				"user_id", reuseErr.UserID,
			)
			h.record(r, authlog.Event{
				Event:   authlog.EventOAuthRefreshReuse,
				Outcome: authlog.OutcomeFailure,
				UserID:  reuseErr.UserID,
				Detail:  "refresh token replay; family revoked app_id=" + reuseErr.AppID,
			})
		}
		h.record(r, authlog.Event{
			Event:   authlog.EventOAuthTokenFailed,
			Outcome: authlog.OutcomeFailure,
			Detail:  "refresh_token",
		})
		h.writeTokenError(w, err)
		return
	}

	h.record(r, authlog.Event{
		Event:   authlog.EventOAuthToken,
		Outcome: authlog.OutcomeSuccess,
		Detail:  "refresh_token",
	})
	h.writeJSON(w, http.StatusOK, resp)
}

// Logout implements OIDC RP-Initiated Logout 1.0 at /oauth/logout.
//
// It accepts GET and POST. The endpoint is intentionally exempt from CSRF
// protection and client authentication: RPs reach it by redirecting or
// auto-submitting the user's browser, and the request is authenticated by the
// signed id_token_hint. A cross-site caller can only terminate the session of
// the browser that is making the request, which is the point of single logout.
// Do not copy this exemption to any other endpoint.
//
// Parameters:
//   - id_token_hint: an id_token issued by this server. Its aud identifies the
//     app, and its registration list authorises post_logout_redirect_uri.
//   - post_logout_redirect_uri: must exactly match a registered redirect URI.
//   - state: echoed back on the redirect when non-empty.
//   - client_id: optional; when present it must match the hint's audience.
//
// Without a hint there is nothing to verify, so the browser is sent to the
// server base URL and post_logout_redirect_uri is ignored (never a redirect
// target). The local SSO session is always revoked.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "failed to parse request")
		return
	}

	idTokenHint := r.FormValue("id_token_hint")
	postLogoutRedirectURI := r.FormValue("post_logout_redirect_uri")
	state := r.FormValue("state")
	clientID := r.FormValue("client_id")

	target := h.baseURL

	if idTokenHint != "" {
		a, err := h.svc.ClientForIDTokenHint(ctx, idTokenHint)
		if err != nil {
			// The reason (bad signature, wrong issuer, unknown client) is
			// logged for operators and never described to the caller.
			h.logger.Warn("oauth logout: id_token_hint rejected", "error", err)
			h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "id_token_hint is not valid")
			return
		}
		if clientID != "" && clientID != a.ClientID {
			h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "client_id does not match id_token_hint")
			return
		}
		if postLogoutRedirectURI != "" {
			// Exact match only: no prefix, suffix, or wildcard comparison.
			registered := false
			for _, uri := range a.RedirectURIs {
				if uri == postLogoutRedirectURI {
					registered = true
					break
				}
			}
			if !registered {
				h.logger.Warn("oauth logout: unregistered post_logout_redirect_uri", "client_id", a.ClientID)
				h.writeJSONError(w, http.StatusBadRequest, "invalid_request",
					"post_logout_redirect_uri is not registered for this client")
				return
			}
			target = postLogoutRedirectURI
		}
	}

	// End the local SSO session. Clear the cookie unconditionally so the
	// browser forgets the token even if the row is already gone, then delete
	// the row — clearing the cookie alone would leave a replayable session.
	session.ClearCookie(w, h.cfg)
	if cookie, err := r.Cookie(h.cfg.Session.EffectiveCookieName()); err == nil && cookie.Value != "" {
		if err := h.sessions.RevokeSession(ctx, cookie.Value); err != nil && !errors.Is(err, session.ErrSessionNotFound) {
			h.logger.Error("oauth logout: revoke session", "error", err)
			h.writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to terminate the session")
			return
		}
	}

	detail := "no id_token_hint"
	if idTokenHint != "" {
		detail = "id_token_hint"
	}
	h.record(r, authlog.Event{
		Event:   authlog.EventOAuthLogout,
		Outcome: authlog.OutcomeSuccess,
		Detail:  detail,
	})

	h.redirectWithState(w, r, target, state)
}

// Revoke implements RFC 7009 token revocation at POST /oauth/revoke.
// It always answers 200 with an empty body once the client is authenticated:
// the response must not reveal whether the token existed. Bad client
// credentials are rejected with 401 invalid_client.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body")
		return
	}

	clientID, clientSecret := extractClientCredentials(r)
	if clientID == "" {
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client credentials are required")
		return
	}

	err := h.svc.RevokeToken(ctx, r.FormValue("token"), r.FormValue("token_type_hint"), clientID, clientSecret)
	if err != nil {
		if isClientAuthError(err) {
			h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
			return
		}
		// Internal failure. RFC 7009 requires 200 for unknown tokens and the
		// response must never leak token state, so log and report success.
		h.logger.Error("oauth revoke: unexpected error", "error", err)
	}

	h.record(r, authlog.Event{
		Event:   authlog.EventOAuthRevoke,
		Outcome: authlog.OutcomeSuccess,
		Detail:  "token_type_hint=" + r.FormValue("token_type_hint"),
	})
	w.WriteHeader(http.StatusOK)
}

// Introspect implements RFC 7662 token introspection at POST /oauth/introspect.
// Active tokens return claims about the token (never the token itself);
// everything else returns {"active": false}.
func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body")
		return
	}

	clientID, clientSecret := extractClientCredentials(r)
	if clientID == "" {
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client credentials are required")
		return
	}

	info, err := h.svc.IntrospectToken(ctx, r.FormValue("token"), r.FormValue("token_type_hint"), clientID, clientSecret)
	if err != nil {
		if isClientAuthError(err) {
			h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
			return
		}
		h.logger.Error("oauth introspect: unexpected error", "error", err)
		h.writeJSONError(w, http.StatusInternalServerError, "server_error", "An unexpected error occurred.")
		return
	}

	if info == nil {
		h.writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}
	h.writeJSON(w, http.StatusOK, info)
}

// isClientAuthError reports whether err is a client-authentication failure
// (as opposed to an internal error).
func isClientAuthError(err error) bool {
	return errors.Is(err, app.ErrInvalidClientSecret) || errors.Is(err, app.ErrOAuthNotEnabled)
}

// redirectWithState redirects to target, appending state as a query parameter
// when one was supplied. target has already been validated by the caller.
func (h *Handler) redirectWithState(w http.ResponseWriter, r *http.Request, target, state string) {
	if target == "" {
		// No configured base URL (development): stay on this host.
		target = "/"
	}
	u, err := url.Parse(target)
	if err != nil {
		h.logger.Error("oauth logout: invalid redirect target", "error", err)
		h.writeJSONError(w, http.StatusInternalServerError, "server_error", "invalid redirect target")
		return
	}
	if state != "" {
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeTokenError maps service errors to RFC 6749 JSON error responses.
// Error descriptions are fixed strings to avoid leaking internal details to clients.
func (h *Handler) writeTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrCodeNotFound),
		errors.Is(err, ErrCodeUsed),
		errors.Is(err, ErrCodeExpired),
		errors.Is(err, ErrRefreshNotFound),
		errors.Is(err, ErrRefreshUsed),
		errors.Is(err, ErrRefreshTokenReuse),
		errors.Is(err, ErrRefreshExpired),
		errors.Is(err, ErrPKCEVerificationFailed),
		errors.Is(err, ErrUserInactive),
		errors.Is(err, ErrAccessRevoked),
		errors.Is(err, app.ErrRedirectURIMismatch):
		h.writeJSONError(w, http.StatusBadRequest, "invalid_grant",
			"The provided authorization grant is invalid, expired, revoked, or does not match.")
	case errors.Is(err, app.ErrInvalidClientSecret),
		errors.Is(err, app.ErrOAuthNotEnabled):
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_client",
			"Client authentication failed.")
	default:
		h.logger.Error("oauth token: unexpected error", "error", err)
		h.writeJSONError(w, http.StatusInternalServerError, "server_error", "An unexpected error occurred.")
	}
}

// UserInfo handles the OAuth2 userinfo endpoint.
// Requires a valid Bearer token in the Authorization header.
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract Bearer token from Authorization header.
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="passage"`)
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="passage"`)
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_token", "Bearer token is empty")
		return
	}

	u, tok, err := h.svc.ValidateAccessToken(ctx, token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="passage", error="invalid_token", error_description="token is expired or invalid"`)
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_token", "token is expired or invalid")
		return
	}

	// Resolve app-scoped roles and effective groups. Assignments come from
	// the same database as the token lookup, so a failure here is a real
	// error condition: fail closed rather than issue claims-stripped output.
	roles, groups, err := h.svc.TokenAssignments(ctx, u.ID, tok.AppID)
	if err != nil {
		h.logger.Error("oauth: userinfo resolve assignments", "user_id", u.ID, "app_id", tok.AppID, "error", err)
		h.writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to resolve user assignments")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"sub":                u.ID,
		"name":               u.Name,
		"email":              u.Email,
		"preferred_username": u.Username,
		// Reports the stored verification flag. Many OIDC clients (e.g. Grist)
		// read this claim; it is informational and never gates sign-in.
		"email_verified": u.EmailVerified,
		"roles":          roles,
		"groups":         groups,
	})
}

// redirectToLogin redirects the user to the login page, preserving the current
// URL as the return destination via the rd query parameter.
func (h *Handler) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.RequestURI()
	loginURL := "/auth/start?rd=" + url.QueryEscape(rd)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// authorizeDenyReason maps an Authorize error to a stable, log-friendly reason
// string. It deliberately does not include the wrapped error text, which can
// carry internal detail.
func authorizeDenyReason(err error) string {
	switch {
	case errors.Is(err, app.ErrOAuthNotEnabled):
		return "oauth_not_enabled"
	case errors.Is(err, app.ErrRedirectURIMismatch):
		return "redirect_uri_mismatch"
	case errors.Is(err, ErrPKCEVerificationFailed):
		return "pkce_failed"
	default:
		return "access_denied"
	}
}

// extractClientCredentials returns the client_id and client_secret from the
// request. It checks HTTP Basic auth first; if not present, it falls back to
// form body fields client_id and client_secret.
func extractClientCredentials(r *http.Request) (clientID, clientSecret string) {
	// HTTP Basic auth takes priority.
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	// Fall back to form body.
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

// writeJSON writes a JSON response with the given status code.
// Encoding errors are logged but cannot be returned to the client since
// headers have already been sent.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Headers already sent; log the failure but cannot change the response.
		h.logger.Error("oauth: failed to encode JSON response", "error", err)
	}
}

// writeJSONError writes an RFC 6749-style JSON error response.
func (h *Handler) writeJSONError(w http.ResponseWriter, status int, errCode, description string) {
	h.writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
