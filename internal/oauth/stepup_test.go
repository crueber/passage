package oauth_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// stepUpStack wires a real OAuth handler and a real session service to one
// in-memory database, so authorization-age decisions run against real session
// rows rather than a fake validator.
type stepUpStack struct {
	handler  *oauth.Handler
	sessions *session.Service
	store    *session.SQLiteStore
	userID   string
}

func buildStepUpStack(t *testing.T, clientID, redirectURI string) *stepUpStack {
	t.Helper()
	ctx := context.Background()

	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	if err := store.EnsureSigningKeys(ctx); err != nil {
		t.Fatalf("buildStepUpStack: EnsureSigningKeys: %v", err)
	}

	testApp := buildTestApp(t, clientID, "test-secret", []string{redirectURI})
	testUser := &user.User{Username: "stepup", Email: "stepup@example.com", Name: "Step Up"}
	appID, userID := seedAppAndUserWithCredentials(t, db, testApp, testUser)
	testApp.ID = appID
	testUser.ID = userID
	testUser.IsActive = true // matches the seeded is_active = 1 row

	apps := &fakeAppClient{app: testApp, access: true}
	users := &fakeUserReader{u: testUser}

	svc, err := oauth.NewService(ctx, store, apps, users, "https://auth.example.com", slog.Default())
	if err != nil {
		t.Fatalf("buildStepUpStack: NewService: %v", err)
	}

	cfg := &config.Config{
		Session: config.SessionConfig{CookieName: "passage_session", DurationHours: 24},
	}
	sessStore := session.NewStore(db)
	sessSvc := session.NewService(sessStore, users, nil, nil, cfg, slog.Default())

	h := oauth.NewHandler(
		svc,
		sessSvc,
		"https://auth.example.com",
		nil,
		cfg,
		slog.Default(),
	)

	return &stepUpStack{handler: h, sessions: sessSvc, store: sessStore, userID: userID}
}

// newSession creates a real session row and returns its cookie plus the
// creation time as a later read sees it (the authentication time the handler
// compares against).
func (s *stepUpStack) newSession(t *testing.T) (*http.Cookie, time.Time) {
	t.Helper()
	ctx := context.Background()

	sess, err := s.sessions.NewSession(ctx, s.userID, nil, "192.0.2.10:4444", "step-up-test")
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	stored, err := s.store.GetByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("newSession: read back session: %v", err)
	}
	return &http.Cookie{Name: "passage_session", Value: sess.ID}, stored.CreatedAt
}

// authorize serves an /oauth/authorize request and returns the response plus
// the raw request URI (the value the login bounce must carry in rd).
func (s *stepUpStack) authorize(t *testing.T, params url.Values, cookie *http.Cookie) (*httptest.ResponseRecorder, string) {
	t.Helper()

	reqURL := "/oauth/authorize?" + params.Encode()
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	newTestRouter(s.handler).ServeHTTP(w, req)
	return w, reqURL
}

// stepUpParams returns the minimal authorization request parameters.
func stepUpParams(clientID, redirectURI string) url.Values {
	return url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
}

// requireErrorRedirect asserts an RFC 6749 error redirect to the client.
func requireErrorRedirect(t *testing.T, w *httptest.ResponseRecorder, wantError, wantState string) *url.URL {
	t.Helper()

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302; body: %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if got := loc.Query().Get("code"); got != "" {
		t.Errorf("error redirect must not carry a code, got %q", got)
	}
	if got := loc.Query().Get("error"); got != wantError {
		t.Errorf("error: got %q, want %q (location %q)", got, wantError, loc.String())
	}
	if wantState != "" {
		if got := loc.Query().Get("state"); got != wantState {
			t.Errorf("state: got %q, want %q", got, wantState)
		}
	}
	return loc
}

// requireCode asserts a successful code redirect.
func requireCode(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302; body: %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if got := loc.Query().Get("error"); got != "" {
		t.Fatalf("expected a code, got error %q", got)
	}
	if got := loc.Query().Get("code"); got == "" {
		t.Fatalf("redirect %q carries no code", loc.String())
	}
	return loc
}

// requireLoginBounce asserts the redirect into the login flow carries the
// original authorization request as its return destination.
func requireLoginBounce(t *testing.T, w *httptest.ResponseRecorder, wantOriginal string) {
	t.Helper()

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302; body: %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if loc.Path != "/auth/start" {
		t.Fatalf("redirect path: got %q, want /auth/start (%q)", loc.Path, loc.String())
	}
	if rd := loc.Query().Get("rd"); rd != wantOriginal {
		t.Errorf("rd: got %q, want the original authorize URL %q", rd, wantOriginal)
	}
}

// requireJSONError asserts an RFC 6749 JSON error response.
func requireJSONError(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantError string) {
	t.Helper()

	if w.Code != wantStatus {
		t.Fatalf("status: got %d, want %d; body: %s", w.Code, wantStatus, w.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body["error"] != wantError {
		t.Errorf("error: got %q, want %q", body["error"], wantError)
	}
}

// TestHandler_Authorize_PromptNone covers prompt=none: no UI may be shown, so a
// request that cannot be authorized immediately must return login_required to
// the client instead of bouncing to the login page.
func TestHandler_Authorize_PromptNone(t *testing.T) {
	const (
		clientID    = "client-stepup-none"
		redirectURI = "https://client.example.com/cb"
	)

	tests := []struct {
		name string
		// requestRedirect overrides redirectURI when non-empty.
		requestRedirect string
		extra           url.Values
		session         bool
		age             time.Duration // handler-clock offset from session creation
		wantStatus      int
		wantError       string
		wantCode        bool
		wantJSONError   string
	}{
		{
			name:       "no_session_returns_login_required",
			extra:      url.Values{"prompt": {"none"}, "state": {"st-none"}},
			wantStatus: http.StatusFound,
			wantError:  "login_required",
		},
		{
			name:       "session_issues_code",
			extra:      url.Values{"prompt": {"none"}, "state": {"st-none"}},
			session:    true,
			wantStatus: http.StatusFound,
			wantCode:   true,
		},
		{
			name:       "session_with_max_age_exceeded_returns_login_required",
			extra:      url.Values{"prompt": {"none"}, "max_age": {"3600"}, "state": {"st-none"}},
			session:    true,
			age:        2 * time.Hour,
			wantStatus: http.StatusFound,
			wantError:  "login_required",
		},
		{
			name:       "session_with_acr_marker_returns_login_required",
			extra:      url.Values{"prompt": {"none"}, "acr_values": {"urn:passage:reauth"}},
			session:    true,
			age:        2 * time.Minute,
			wantStatus: http.StatusFound,
			wantError:  "login_required",
		},
		{
			// OIDC Core §3.1.2.1: none combined with any other value is an error.
			name:          "none_combined_with_login_is_invalid_request",
			extra:         url.Values{"prompt": {"none login"}},
			wantStatus:    http.StatusBadRequest,
			wantJSONError: "invalid_request",
		},
		{
			// There is no validated redirect_uri to answer on, so the request
			// must fall back to the JSON error path instead of redirecting to an
			// unregistered URL.
			name:            "unregistered_redirect_uri_falls_back_to_json",
			requestRedirect: "https://evil.example.com/cb",
			extra:           url.Values{"prompt": {"none"}},
			wantStatus:      http.StatusBadRequest,
			wantJSONError:   "invalid_request",
		},
	}

	stack := buildStepUpStack(t, clientID, redirectURI)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requestRedirect := redirectURI
			if tc.requestRedirect != "" {
				requestRedirect = tc.requestRedirect
			}
			params := stepUpParams(clientID, requestRedirect)
			for k, v := range tc.extra {
				params[k] = v
			}

			var cookie *http.Cookie
			base := time.Now()
			if tc.session {
				var created time.Time
				cookie, created = stack.newSession(t)
				base = created
			}
			stack.handler.SetClock(func() time.Time { return base.Add(tc.age) })

			w, _ := stack.authorize(t, params, cookie)

			switch {
			case tc.wantJSONError != "":
				requireJSONError(t, w, tc.wantStatus, tc.wantJSONError)
			case tc.wantError != "":
				loc := requireErrorRedirect(t, w, tc.wantError, params.Get("state"))
				if loc.Host != "client.example.com" {
					t.Errorf("error redirect host: got %q, want client.example.com", loc.Host)
				}
			case tc.wantCode:
				loc := requireCode(t, w)
				if got := loc.Query().Get("state"); got != params.Get("state") {
					t.Errorf("state: got %q, want %q", got, params.Get("state"))
				}
			default:
				t.Fatalf("test case has no expectation")
			}
		})
	}
}

// TestHandler_Authorize_PromptLogin covers prompt=login: an existing session is
// not enough; the authentication must be no older than the freshness window.
func TestHandler_Authorize_PromptLogin(t *testing.T) {
	const (
		clientID    = "client-stepup-login"
		redirectURI = "https://client.example.com/cb"
	)

	tests := []struct {
		name       string
		session    bool
		age        time.Duration
		wantBounce bool
		wantCode   bool
	}{
		{name: "old_session_bounces", session: true, age: 61 * time.Second, wantBounce: true},
		{name: "exactly_at_window_passes", session: true, age: 60 * time.Second, wantCode: true},
		{name: "just_past_window_bounces", session: true, age: 60*time.Second + time.Nanosecond, wantBounce: true},
		{name: "fresh_session_passes", session: true, age: 0, wantCode: true},
		{name: "no_session_bounces", wantBounce: true},
	}

	stack := buildStepUpStack(t, clientID, redirectURI)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := stepUpParams(clientID, redirectURI)
			params.Set("prompt", "login")

			var cookie *http.Cookie
			base := time.Now()
			if tc.session {
				var created time.Time
				cookie, created = stack.newSession(t)
				base = created
			}
			stack.handler.SetClock(func() time.Time { return base.Add(tc.age) })

			w, reqURL := stack.authorize(t, params, cookie)

			switch {
			case tc.wantBounce:
				requireLoginBounce(t, w, reqURL)
			case tc.wantCode:
				requireCode(t, w)
			default:
				t.Fatalf("test case has no expectation")
			}
		})
	}
}

// TestHandler_Authorize_MaxAge covers max_age parsing and the age boundary.
func TestHandler_Authorize_MaxAge(t *testing.T) {
	const (
		clientID    = "client-stepup-maxage"
		redirectURI = "https://client.example.com/cb"
	)

	tests := []struct {
		name string
		// maxAge is the raw parameter; maxAgeSet distinguishes absent from empty.
		maxAge     string
		maxAgeSet  bool
		age        time.Duration
		wantBounce bool
		wantCode   bool
		wantStatus int
		wantJSON   string
	}{
		{name: "absent_accepts_old_session", age: 10 * time.Hour, wantCode: true},
		{name: "exactly_n_passes", maxAge: "3600", maxAgeSet: true, age: time.Hour, wantCode: true},
		{
			name: "n_plus_one_nanosecond_bounces", maxAge: "3600", maxAgeSet: true,
			age: time.Hour + time.Nanosecond, wantBounce: true,
		},
		{name: "zero_with_fresh_session_passes", maxAge: "0", maxAgeSet: true, age: 0, wantCode: true},
		{name: "zero_with_old_session_bounces", maxAge: "0", maxAgeSet: true, age: 2 * time.Minute, wantBounce: true},
		{
			name: "empty_value_is_invalid", maxAge: "", maxAgeSet: true,
			wantStatus: http.StatusBadRequest, wantJSON: "invalid_request",
		},
		{
			name: "non_numeric_is_invalid", maxAge: "abc", maxAgeSet: true,
			wantStatus: http.StatusBadRequest, wantJSON: "invalid_request",
		},
		{
			name: "negative_is_invalid", maxAge: "-1", maxAgeSet: true,
			wantStatus: http.StatusBadRequest, wantJSON: "invalid_request",
		},
		{
			name: "overflowing_int64_is_invalid", maxAge: "9223372036854775808", maxAgeSet: true,
			wantStatus: http.StatusBadRequest, wantJSON: "invalid_request",
		},
		{
			name: "duration_overflow_is_invalid", maxAge: "9223372037", maxAgeSet: true,
			wantStatus: http.StatusBadRequest, wantJSON: "invalid_request",
		},
	}

	stack := buildStepUpStack(t, clientID, redirectURI)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := stepUpParams(clientID, redirectURI)
			if tc.maxAgeSet {
				params["max_age"] = []string{tc.maxAge}
			}

			cookie, created := stack.newSession(t)
			stack.handler.SetClock(func() time.Time { return created.Add(tc.age) })

			w, reqURL := stack.authorize(t, params, cookie)

			switch {
			case tc.wantJSON != "":
				requireJSONError(t, w, tc.wantStatus, tc.wantJSON)
			case tc.wantBounce:
				requireLoginBounce(t, w, reqURL)
			case tc.wantCode:
				requireCode(t, w)
			default:
				t.Fatalf("test case has no expectation")
			}
		})
	}
}

// TestHandler_Authorize_ACRValues covers acr_values: only the documented
// urn:passage:reauth marker affects the decision; everything else is ignored.
func TestHandler_Authorize_ACRValues(t *testing.T) {
	const (
		clientID    = "client-stepup-acr"
		redirectURI = "https://client.example.com/cb"
	)

	tests := []struct {
		name       string
		acrValues  string
		age        time.Duration
		wantBounce bool
		wantCode   bool
	}{
		{name: "marker_old_session_bounces", acrValues: "urn:passage:reauth", age: 2 * time.Minute, wantBounce: true},
		{name: "marker_exactly_at_window_passes", acrValues: "urn:passage:reauth", age: 60 * time.Second, wantCode: true},
		{name: "marker_fresh_session_passes", acrValues: "urn:passage:reauth", age: 0, wantCode: true},
		{name: "unknown_marker_is_ignored", acrValues: "urn:example:other", age: 2 * time.Minute, wantCode: true},
		{
			name:      "marker_among_several_values_bounces",
			acrValues: "urn:example:one urn:passage:reauth urn:example:two",
			age:       2 * time.Minute, wantBounce: true,
		},
		{
			name:      "several_values_without_marker_are_ignored",
			acrValues: "urn:example:one urn:example:two",
			age:       2 * time.Minute, wantCode: true,
		},
	}

	stack := buildStepUpStack(t, clientID, redirectURI)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := stepUpParams(clientID, redirectURI)
			params.Set("acr_values", tc.acrValues)

			cookie, created := stack.newSession(t)
			stack.handler.SetClock(func() time.Time { return created.Add(tc.age) })

			w, reqURL := stack.authorize(t, params, cookie)

			switch {
			case tc.wantBounce:
				requireLoginBounce(t, w, reqURL)
			case tc.wantCode:
				requireCode(t, w)
			default:
				t.Fatalf("test case has no expectation")
			}
		})
	}
}

// TestHandler_Authorize_NoRedirectLoop replays a step-up: after the login flow
// creates a new session, the same authorization request must issue a code.
func TestHandler_Authorize_NoRedirectLoop(t *testing.T) {
	const (
		clientID    = "client-stepup-loop"
		redirectURI = "https://client.example.com/cb"
	)
	stack := buildStepUpStack(t, clientID, redirectURI)
	params := stepUpParams(clientID, redirectURI)
	params.Set("prompt", "login")

	oldCookie, oldCreated := stack.newSession(t)
	stack.handler.SetClock(func() time.Time { return oldCreated.Add(5 * time.Minute) })

	// First attempt: the old session is not fresh, so the browser is sent to sign in.
	w, reqURL := stack.authorize(t, params, oldCookie)
	requireLoginBounce(t, w, reqURL)

	// The login flow completes and creates a new session for the user. The old
	// session is left untouched — step-up never rotates sessions.
	newCookie, _ := stack.newSession(t)
	stack.handler.SetClock(time.Now)

	// Second attempt, same request: the new session is fresh, so a code is issued.
	w, _ = stack.authorize(t, params, newCookie)
	requireCode(t, w)

	if _, err := stack.store.GetByID(context.Background(), oldCookie.Value); err != nil {
		t.Errorf("old session must survive step-up, got error: %v", err)
	}
}

// TestHandler_Authorize_UnchangedWithoutReauthParams pins that requests without
// prompt, max_age or acr_values behave exactly as before: no freshness check,
// and the existing PKCE / redirect_uri validation still applies.
func TestHandler_Authorize_UnchangedWithoutReauthParams(t *testing.T) {
	const (
		clientID    = "client-stepup-plain"
		redirectURI = "https://client.example.com/cb"
	)
	stack := buildStepUpStack(t, clientID, redirectURI)

	cookie, created := stack.newSession(t)
	stack.handler.SetClock(func() time.Time { return created.Add(10 * time.Hour) })

	// A ten-hour-old session still authorizes when nothing asks for freshness,
	// and a valid PKCE challenge is accepted as before.
	params := stepUpParams(clientID, redirectURI)
	params.Set("code_challenge", strings.Repeat("a", 43))
	params.Set("code_challenge_method", "S256")
	params.Set("state", "plain-state")

	w, _ := stack.authorize(t, params, cookie)
	loc := requireCode(t, w)
	if got := loc.Query().Get("state"); got != "plain-state" {
		t.Errorf("state: got %q, want plain-state", got)
	}

	// Redirect-URI validation is unchanged.
	badParams := stepUpParams(clientID, "https://evil.example.com/cb")
	w, _ = stack.authorize(t, badParams, cookie)
	requireJSONError(t, w, http.StatusBadRequest, "invalid_request")

	// Unsupported prompt values are ignored, not treated as a re-auth demand.
	ignored := stepUpParams(clientID, redirectURI)
	ignored.Set("prompt", "consent select_account")
	w, _ = stack.authorize(t, ignored, cookie)
	requireCode(t, w)
}
