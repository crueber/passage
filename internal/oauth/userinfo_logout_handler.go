package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/session"
)

// UserInfo handles the OAuth2 userinfo endpoint.
// Requires a valid Bearer token in the Authorization header.
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Extract Bearer token from Authorization header (case-insensitive scheme per RFC 7235 §2.1).
	authHeader := r.Header.Get("Authorization")
	scheme, rawToken, hasSpace := strings.Cut(authHeader, " ")
	if !hasSpace || !strings.EqualFold(scheme, "Bearer") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="passage"`)
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
		return
	}

	token := strings.TrimSpace(rawToken)
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
