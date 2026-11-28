package oauth

import (
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
)

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
	// RFC 8707 allows a repeated resource parameter, but a Passage access
	// token has exactly one audience, so more than one is refused rather than
	// silently narrowed.
	if len(q["resource"]) > 1 {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_target", "only one resource indicator is supported")
		return
	}
	resource := q.Get("resource")

	// Validate the OIDC re-authentication parameters. A malformed value is the
	// client's own error and is answered before any session work, so it never
	// turns into a login bounce.
	prompts, err := parseReauthParameters(q)
	if err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Validate the session. A request may legitimately have no session: the
	// login bounce below brings the browser back here with a fresh one.
	var sess *session.Session
	var u *user.User
	cookie, cookieErr := r.Cookie(h.cfg.Session.EffectiveCookieName())
	if cookieErr == nil {
		sess, u, err = h.sessions.ValidateSession(ctx, cookie.Value)
	}
	if cookieErr != nil || err != nil {
		if prompts.none {
			// prompt=none forbids showing any UI, so the client is told that
			// authentication is required instead of being sent to the login page.
			h.redirectLoginRequired(w, r, clientID, redirectURI, state)
			return
		}
		h.redirectToLogin(w, r)
		return
	}

	// Step-up: prompt=login, max_age, and acr_values=urn:passage:reauth all ask
	// for a *fresh* authentication rather than merely an existing session. The
	// session's authentication time is its creation time (the same value the
	// id_token reports as auth_time).
	if prompts.requiresFreshAuth(sess.CreatedAt, h.currentTime()) {
		if prompts.none {
			h.redirectLoginRequired(w, r, clientID, redirectURI, state)
			return
		}
		// Send the browser through the login flow and straight back to this
		// exact authorization request. The freshness window is the loop guard:
		// the login flow always creates a *new* session, so the request that
		// comes back is fresh and this branch is not taken again. The existing
		// session is left intact — step-up adds a session, it never rotates or
		// revokes the old one.
		h.redirectToLogin(w, r)
		return
	}

	// Attempt to authorize.
	code, err := h.svc.Authorize(ctx, clientID, redirectURI, scope, resource, state, nonce, codeChallenge, codeChallengeMethod, sess.CreatedAt, u.ID, authlog.ClientIP(r))
	if err != nil {
		h.record(r, authlog.Event{
			Event:    authlog.EventOAuthAuthorize,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   authorizeDenyReason(err) + " client_id=" + clientID,
		})
		// The app's access policy is the only denial that gets its own event;
		// the shared helper records it and the fixed description below never
		// names the failing rule.
		policyDenied := h.recordPolicyDenial(r, err)
		switch {
		case policyDenied:
			h.writeJSONError(w, http.StatusForbidden, "access_denied",
				"The resource owner or authorization server denied the request.")
		case errors.Is(err, app.ErrOAuthNotEnabled),
			errors.Is(err, app.ErrRedirectURIMismatch),
			errors.Is(err, ErrPKCEVerificationFailed),
			errors.Is(err, ErrInvalidScope),
			errors.Is(err, ErrInvalidTarget):
			h.writeAuthorizeClientError(w, err)
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

// redirectToLogin redirects the user to the login page, preserving the current
// URL as the return destination via the rd query parameter.
func (h *Handler) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.RequestURI()
	loginURL := "/auth/start?rd=" + url.QueryEscape(rd)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

const (
	// reauthWindow is how recently a session must have been created to count as
	// a fresh authentication for prompt=login and acr_values=urn:passage:reauth.
	// It only needs to cover the round trip through the login flow, and it is
	// the loop guard for the re-authentication bounce.
	reauthWindow = 60 * time.Second

	// acrReauth is the only acr_values entry Passage recognises. It asks for a
	// fresh authentication and is satisfied by reauthWindow. Other acr_values
	// entries are ignored: Passage does not implement other authentication
	// context classes, and OIDC Core §3.1.2.1 lets the OP ignore unknown
	// requested values.
	acrReauth = "urn:passage:reauth"

	// maxMaxAgeSeconds caps max_age at the largest number of seconds that fits
	// in a time.Duration, so a hostile value cannot overflow the age comparison.
	maxMaxAgeSeconds = int64(math.MaxInt64 / int64(time.Second))
)

// reauthParameters are the OIDC re-authentication parameters of an
// authorization request.
type reauthParameters struct {
	none      bool // prompt=none: never show UI; answer login_required instead
	login     bool // prompt=login: require a fresh authentication
	maxAge    *time.Duration
	acrReauth bool // acr_values named urn:passage:reauth
}

// parseReauthParameters parses prompt, max_age, and acr_values. Unknown prompt
// and acr_values entries are ignored (OIDC Core §3.1.2.1 allows that); a
// malformed max_age and prompt=none combined with another prompt value are
// invalid_request. The returned errors are fixed strings safe to show clients.
func parseReauthParameters(q url.Values) (reauthParameters, error) {
	var p reauthParameters

	promptValues := strings.Fields(q.Get("prompt"))
	for _, v := range promptValues {
		switch v {
		case "none":
			p.none = true
		case "login":
			p.login = true
		}
	}
	if p.none && len(promptValues) > 1 {
		return reauthParameters{}, errors.New("prompt=none must not be combined with other prompt values")
	}

	for _, v := range strings.Fields(q.Get("acr_values")) {
		if v == acrReauth {
			p.acrReauth = true
		}
	}

	if q.Has("max_age") {
		n, err := strconv.ParseInt(q.Get("max_age"), 10, 64)
		if err != nil || n < 0 || n > maxMaxAgeSeconds {
			return reauthParameters{}, errors.New("max_age must be a non-negative integer number of seconds")
		}
		d := time.Duration(n) * time.Second
		p.maxAge = &d
	}

	return p, nil
}

// requiresFreshAuth reports whether the request demands a more recent
// authentication than authTime provides. The caller decides what to do about
// it: a login bounce, or login_required for prompt=none.
func (p reauthParameters) requiresFreshAuth(authTime, now time.Time) bool {
	if (p.login || p.acrReauth) && now.Sub(authTime) > reauthWindow {
		return true
	}
	if p.maxAge == nil {
		return false
	}
	window := *p.maxAge
	if window == 0 {
		// max_age=0 means "authenticate again now". It is treated as the same
		// freshness window as prompt=login, which is what stops a loop: a
		// literal "age > 0" test would fail for every session, including the
		// one the login flow has just created.
		window = reauthWindow
	}
	return now.Sub(authTime) > window
}

// redirectLoginRequired answers a prompt=none authorization request that cannot
// be satisfied without showing UI. The error may only be delivered to a
// redirect_uri registered to the client; when there is none, the request falls
// back to the JSON error path so the endpoint never becomes an open redirector.
func (h *Handler) redirectLoginRequired(w http.ResponseWriter, r *http.Request, clientID, redirectURI, state string) {
	if err := h.svc.ValidateClientRedirectURI(r.Context(), clientID, redirectURI); err != nil {
		h.writeAuthorizeClientError(w, err)
		return
	}
	h.redirectAuthError(w, r, redirectURI, state, "login_required")
}

// redirectAuthError redirects to an already validated redirect_uri with an
// RFC 6749 §4.1.2.1 error response.
func (h *Handler) redirectAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is malformed")
		return
	}
	q := target.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// writeAuthorizeClientError writes the JSON error for the client-side failures
// of an authorization request. Descriptions are fixed strings so internal
// detail never reaches a client.
func (h *Handler) writeAuthorizeClientError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, app.ErrOAuthNotEnabled):
		h.writeJSONError(w, http.StatusBadRequest, "unauthorized_client",
			"OAuth is not enabled for this client")
	case errors.Is(err, app.ErrRedirectURIMismatch):
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request",
			"redirect_uri does not match registered URIs")
	case errors.Is(err, ErrPKCEVerificationFailed):
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request",
			"invalid code_challenge or code_challenge_method")
	case errors.Is(err, ErrInvalidScope):
		h.writeJSONError(w, http.StatusBadRequest, "invalid_scope",
			"One or more requested scopes are not allowed for this client.")
	case errors.Is(err, ErrInvalidTarget):
		h.writeJSONError(w, http.StatusBadRequest, "invalid_target",
			"The requested resource is not allowed for this client.")
	default:
		h.logger.Warn("oauth authorize: client validation failed", "error", err)
		h.writeJSONError(w, http.StatusForbidden, "access_denied",
			"The resource owner or authorization server denied the request.")
	}
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
	case errors.Is(err, ErrInvalidScope):
		return "invalid_scope"
	case errors.Is(err, ErrInvalidTarget):
		return "invalid_target"
	default:
		return "access_denied"
	}
}
