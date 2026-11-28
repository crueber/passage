package oauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
)

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

	// A Passage access token has exactly one audience, so a repeated resource
	// parameter is refused rather than silently narrowed (RFC 8707 permits
	// multiple; the response cannot represent them).
	if len(r.PostForm["resource"]) > 1 {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_target", "only one resource indicator is supported")
		return
	}

	grantType := r.PostFormValue("grant_type")

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
	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	codeVerifier := r.PostFormValue("code_verifier")
	resource := r.PostFormValue("resource")

	if code == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	if redirectURI == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}

	resp, err := h.svc.ExchangeCode(ctx, code, clientID, clientSecret, redirectURI, codeVerifier, resource, authlog.ClientIP(r))
	if err != nil {
		h.record(r, authlog.Event{
			Event:   authlog.EventOAuthTokenFailed,
			Outcome: authlog.OutcomeFailure,
			Detail:  "authorization_code",
		})
		h.recordPolicyDenial(r, err)
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
	refreshToken := r.PostFormValue("refresh_token")
	if refreshToken == "" {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	resp, err := h.svc.RefreshTokens(ctx, refreshToken, clientID, clientSecret, r.PostFormValue("resource"), r.PostFormValue("scope"), authlog.ClientIP(r))
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
		h.recordPolicyDenial(r, err)
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

	hint := r.PostFormValue("token_type_hint")
	err := h.svc.RevokeToken(ctx, r.PostFormValue("token"), hint, clientID, clientSecret)
	if err != nil {
		if isClientAuthError(err) {
			h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
			return
		}
		// RFC 7009 §2.2.1: storage/internal failures return 503 so clients know
		// revocation could not be persisted (200 is for unknown/invalid tokens).
		h.logger.Error("oauth revoke: unexpected error", "error", err)
		h.record(r, authlog.Event{
			Event:   authlog.EventOAuthRevoke,
			Outcome: authlog.OutcomeFailure,
			Detail:  "revocation failed",
		})
		h.writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Unable to revoke token; please retry.")
		return
	}

	safeHint := ""
	if hint == tokenKindAccess || hint == tokenKindRefresh {
		safeHint = hint
	}
	h.record(r, authlog.Event{
		Event:   authlog.EventOAuthRevoke,
		Outcome: authlog.OutcomeSuccess,
		Detail:  "token_type_hint=" + safeHint,
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

	info, err := h.svc.IntrospectToken(ctx, r.PostFormValue("token"), r.PostFormValue("token_type_hint"), clientID, clientSecret)
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
		errors.Is(err, ErrAccessDeniedByPolicy),
		errors.Is(err, app.ErrRedirectURIMismatch):
		h.writeJSONError(w, http.StatusBadRequest, "invalid_grant",
			"The provided authorization grant is invalid, expired, revoked, or does not match.")
	case errors.Is(err, ErrInvalidScope):
		h.writeJSONError(w, http.StatusBadRequest, "invalid_scope",
			"One or more requested scopes are not allowed for this client.")
	case errors.Is(err, ErrInvalidTarget):
		h.writeJSONError(w, http.StatusBadRequest, "invalid_target",
			"The requested resource is not allowed for this client.")
	case errors.Is(err, app.ErrInvalidClientSecret),
		errors.Is(err, app.ErrOAuthNotEnabled):
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_client",
			"Client authentication failed.")
	default:
		h.logger.Error("oauth token: unexpected error", "error", err)
		h.writeJSONError(w, http.StatusInternalServerError, "server_error", "An unexpected error occurred.")
	}
}
