package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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
	Authorize(ctx context.Context, clientID, redirectURI, scope, resource, state, nonce, codeChallenge, codeChallengeMethod string, sessionCreatedAt time.Time, userID, clientIP string) (*Code, error)
	// ValidateClientRedirectURI checks the client and its redirect_uri without
	// issuing a code, for authorization requests that must be answered before a
	// session is resolved (prompt=none).
	ValidateClientRedirectURI(ctx context.Context, clientID, redirectURI string) error
	ExchangeCode(ctx context.Context, code, clientID, clientSecret, redirectURI, codeVerifier, resource, clientIP string) (*TokenResponse, error)
	RefreshTokens(ctx context.Context, refreshToken, clientID, clientSecret, resource, scope, clientIP string) (*TokenResponse, error)
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
	// now is the handler's time source. It is time.Now unless a test overrides
	// it with SetClock, so authentication-age boundaries are deterministic.
	now func() time.Time
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(svc oauthService, sessions sessionValidator, baseURL string, authEvents authEventRecorder, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		svc:        svc,
		sessions:   sessions,
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		authEvents: authEvents,
		cfg:        cfg,
		logger:     logger,
		now:        time.Now,
	}
}

// SetClock replaces the handler's time source. It exists for tests that need
// deterministic authentication-age boundaries and must be called before the
// handler serves requests.
func (h *Handler) SetClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	h.now = now
}

// currentTime returns the handler's current time.
func (h *Handler) currentTime() time.Time {
	if h.now == nil {
		return time.Now()
	}
	return h.now()
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

// isClientAuthError reports whether err is a client-authentication failure
// (as opposed to an internal error).
func isClientAuthError(err error) bool {
	return errors.Is(err, app.ErrInvalidClientSecret) || errors.Is(err, app.ErrOAuthNotEnabled)
}

// recordPolicyDenial logs and records an access-policy denial. It reports
// whether err was one, so each caller can write the response the endpoint
// calls for: access_denied at authorize, invalid_grant at the token endpoint.
// The failing rule stays in the log and the event, never in the response.
func (h *Handler) recordPolicyDenial(r *http.Request, err error) bool {
	var denial *PolicyDenialError
	if !errors.As(err, &denial) {
		return false
	}
	h.logger.Info("oauth: access policy denied",
		"user_id", denial.UserID, "username", denial.Username,
		"app_slug", denial.AppSlug, "reason", denial.Reason,
		"client_ip", authlog.ClientIP(r))
	h.record(r, authlog.Event{
		Event:    authlog.EventAccessDenied,
		Outcome:  authlog.OutcomeFailure,
		UserID:   denial.UserID,
		Username: denial.Username,
		Detail:   "app=" + denial.AppSlug + " reason=" + denial.Reason,
	})
	return true
}

// extractClientCredentials returns the client_id and client_secret from the
// request. It checks HTTP Basic auth first; if not present, it falls back to
// form body fields client_id and client_secret.
func extractClientCredentials(r *http.Request) (clientID, clientSecret string) {
	// HTTP Basic auth takes priority.
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	// Fall back to POST form body only (never URL query parameters).
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
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
