package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

// oauthService is the interface the Handler uses for OAuth operations.
// Defined here at the consumer boundary, per Go convention.
type oauthService interface {
	Authorize(ctx context.Context, clientID, redirectURI, scope, state, userID string) (*Code, error)
	ExchangeCode(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenResponse, error)
	RefreshTokens(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenResponse, error)
	ValidateAccessToken(ctx context.Context, token string) (*user.User, *Token, error)
}

// sessionValidator is the interface the Handler uses to validate sessions.
// Defined here at the consumer boundary, per Go convention.
type sessionValidator interface {
	ValidateSession(ctx context.Context, token string) (*session.Session, *user.User, error)
}

// Handler handles OAuth2/OIDC HTTP requests.
type Handler struct {
	svc        oauthService
	sessions   sessionValidator
	publicKey  *rsa.PublicKey
	keyID      string // kid included in JWKS and id_token header
	baseURL    string
	cookieName string
	logger     *slog.Logger
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(svc oauthService, sessions sessionValidator, publicKey *rsa.PublicKey, keyID, baseURL, cookieName string, logger *slog.Logger) *Handler {
	return &Handler{
		svc:        svc,
		sessions:   sessions,
		publicKey:  publicKey,
		keyID:      keyID,
		baseURL:    baseURL,
		cookieName: cookieName,
		logger:     logger,
	}
}

// Routes registers the OAuth2/OIDC routes on the given router.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.Discovery)
	r.Get("/.well-known/jwks.json", h.JWKS)
	r.Get("/oauth/authorize", h.Authorize)
	r.Post("/oauth/token", h.Token)
	r.Get("/oauth/userinfo", h.UserInfo)
}

// Discovery returns the OpenID Connect discovery document.
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                h.baseURL,
		"authorization_endpoint":                h.baseURL + "/oauth/authorize",
		"token_endpoint":                        h.baseURL + "/oauth/token",
		"userinfo_endpoint":                     h.baseURL + "/oauth/userinfo",
		"jwks_uri":                              h.baseURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "preferred_username"},
	}

	h.writeJSON(w, http.StatusOK, doc)
}

// JWKS returns the JSON Web Key Set containing the RSA public key used to
// verify id_token signatures.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	pub := h.publicKey

	// Encode the modulus (n) as base64url with no padding.
	nBytes := pub.N.Bytes()
	nEncoded := base64.RawURLEncoding.EncodeToString(nBytes)

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

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": h.keyID,
				"n":   nEncoded,
				"e":   eEncoded,
			},
		},
	}

	h.writeJSON(w, http.StatusOK, jwks)
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
	cookie, err := r.Cookie(h.cookieName)
	if err != nil {
		// No session cookie — redirect to login.
		h.redirectToLogin(w, r)
		return
	}

	_, u, err := h.sessions.ValidateSession(ctx, cookie.Value)
	if err != nil {
		h.redirectToLogin(w, r)
		return
	}

	// Attempt to authorize.
	code, err := h.svc.Authorize(ctx, clientID, redirectURI, scope, state, u.ID)
	if err != nil {
		if errors.Is(err, app.ErrRedirectURIMismatch) || errors.Is(err, app.ErrOAuthNotEnabled) {
			h.writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		h.logger.Warn("oauth authorize: access denied", "user_id", u.ID, "error", err)
		h.writeJSONError(w, http.StatusForbidden, "access_denied", err.Error())
		return
	}

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

	if code == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	if redirectURI == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}

	resp, err := h.svc.ExchangeCode(ctx, code, clientID, clientSecret, redirectURI)
	if err != nil {
		h.writeTokenError(w, err)
		return
	}

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
		h.writeTokenError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
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
		errors.Is(err, ErrRefreshExpired),
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

	u, _, err := h.svc.ValidateAccessToken(ctx, token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="passage", error="invalid_token", error_description="token is expired or invalid"`)
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_token", "token is expired or invalid")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{
		"sub":                u.ID,
		"name":               u.Name,
		"email":              u.Email,
		"preferred_username": u.Username,
	})
}

// redirectToLogin redirects the user to the login page, preserving the current
// URL as the return destination via the rd query parameter.
func (h *Handler) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.RequestURI()
	loginURL := "/auth/start?rd=" + url.QueryEscape(rd)
	http.Redirect(w, r, loginURL, http.StatusFound)
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
