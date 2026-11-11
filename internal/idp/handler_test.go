package idp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/idp"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

const (
	testProviderName = "authentik"
	testClientID     = "passage-test"
	testClientSecret = "shhh"
	testCode         = "test-code"
)

var (
	sharedKeyOnce sync.Once
	sharedKey     *rsa.PrivateKey
	sharedKeyErr  error
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	sharedKeyOnce.Do(func() {
		sharedKey, sharedKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if sharedKeyErr != nil {
		t.Fatalf("generate RSA test key: %v", sharedKeyErr)
	}
	return sharedKey
}

// fakeProvider is a minimal OIDC provider: discovery, JWKS, and a token
// endpoint that returns an id_token signed with the shared test key. It lets a
// test swap any claim (issuer, audience, expiry, nonce, email_verified).
type fakeProvider struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	mu           sync.Mutex
	claims       jwtlib.MapClaims
	rawIDToken   string
	nonce        string
	tokenStatus  int
	lastVerifier string
	tokenCalls   int
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	f := &fakeProvider{
		t:   t,
		key: testKey(t),
		kid: "test-key",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := f.server.URL
		writeJSON(t, w, map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA",
			"kid": f.kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenCalls++
		f.lastVerifier = r.FormValue("code_verifier")

		if f.tokenStatus != 0 && f.tokenStatus != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.tokenStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code") != testCode {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		if r.FormValue("code_verifier") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_request"})
			return
		}

		raw := f.rawIDToken
		if raw == "" {
			claims := jwtlib.MapClaims{}
			for k, v := range f.claims {
				claims[k] = v
			}
			claims["nonce"] = f.nonce
			tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
			tok.Header["kid"] = f.kid
			signed, err := tok.SignedString(f.key)
			if err != nil {
				http.Error(w, "sign failed", http.StatusInternalServerError)
				return
			}
			raw = signed
		}
		writeJSON(t, w, map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"id_token":     raw,
		})
	})

	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	f.resetClaims()
	return f
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("write JSON response: %v", err)
	}
}

// resetClaims installs a valid, verifiable id_token claim set.
func (f *fakeProvider) resetClaims() {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = jwtlib.MapClaims{
		"iss":                f.server.URL,
		"aud":                testClientID,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"sub":                "subject-alice",
		"email":              "alice@example.com",
		"email_verified":     true,
		"name":               "Alice Example",
		"preferred_username": "alice",
	}
	f.rawIDToken = ""
	f.tokenStatus = 0
}

func (f *fakeProvider) setClaim(name string, value any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims[name] = value
}

func (f *fakeProvider) deleteClaim(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.claims, name)
}

func (f *fakeProvider) setNonce(nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce = nonce
}

func (f *fakeProvider) setRawIDToken(raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rawIDToken = raw
}

func (f *fakeProvider) verifier() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastVerifier
}

func (f *fakeProvider) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenCalls
}

// mapSettings is a settingsReader backed by a map; a missing key falls back to
// the handler's config default.
type mapSettings struct {
	values map[string]string
}

func (s *mapSettings) Get(_ context.Context, key string) (string, error) {
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}

type fixture struct {
	t         *testing.T
	db        *sql.DB
	handler   *idp.Handler
	cfg       *config.Config
	userSvc   *user.Service
	userStore *user.SQLiteStore
	links     *idp.SQLiteStore
	sessions  *session.Service
	authStore *authlog.Store
	settings  *mapSettings
	fake      *fakeProvider
	server    *httptest.Server
	client    *http.Client
}

func newFixture(t *testing.T, autoCreate bool) *fixture {
	t.Helper()

	fake := newFakeProvider(t)
	database := testutil.NewTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &config.Config{
		Server: config.ServerConfig{BaseURL: "https://passage.test"},
		Auth: config.AuthConfig{
			AllowRegistration: true,
			BcryptCost:        10,
			Providers: []config.ProviderConfig{{
				Name:         testProviderName,
				Label:        "Authentik",
				Issuer:       fake.server.URL,
				ClientID:     testClientID,
				ClientSecret: testClientSecret,
				AutoCreate:   autoCreate,
			}},
		},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
	}

	userStore := user.NewStore(database)
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	sessionSvc := session.NewService(session.NewStore(database), userStore, nil, nil, cfg, logger)
	appStore := app.NewStore(database)
	appSvc := app.NewService(appStore, appStore, logger)
	linkStore := idp.NewStore(database)
	authStore := authlog.NewStore(database)
	authRecorder := authlog.NewRecorder(authStore, nil, logger)
	settings := &mapSettings{values: map[string]string{}}

	handler := idp.NewHandler(
		linkStore,
		userSvc,
		appSvc,
		sessionSvc,
		settings,
		authRecorder,
		idp.NewClient(fake.server.Client()),
		cfg,
		logger,
	)

	router := chi.NewRouter()
	handler.Routes(router)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// The redirect URI registered with the provider must use the test server,
	// so the callback matches.
	cfg.Server.BaseURL = srv.URL

	return &fixture{
		t:         t,
		db:        database,
		handler:   handler,
		cfg:       cfg,
		userSvc:   userSvc,
		userStore: userStore,
		links:     linkStore,
		sessions:  sessionSvc,
		authStore: authStore,
		settings:  settings,
		fake:      fake,
		server:    srv,
		client:    client,
	}
}

func (f *fixture) start(rd string) (state, nonce string) {
	f.t.Helper()
	target := f.server.URL + "/login/oidc/" + testProviderName + "/start"
	if rd != "" {
		target += "?rd=" + url.QueryEscape(rd)
	}
	resp, err := f.client.Get(target)
	if err != nil {
		f.t.Fatalf("GET start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		f.t.Fatalf("start status = %d; want 302 (body: %s)", resp.StatusCode, readBody(resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		f.t.Fatalf("parse start Location: %v", err)
	}
	state = loc.Query().Get("state")
	nonce = loc.Query().Get("nonce")
	if state == "" || nonce == "" {
		f.t.Fatalf("authorization URL missing state/nonce: %s", loc)
	}
	if loc.Query().Get("code_challenge") == "" || loc.Query().Get("code_challenge_method") != "S256" {
		f.t.Fatalf("authorization URL missing PKCE S256 challenge: %s", loc)
	}
	f.fake.setNonce(nonce)
	return state, nonce
}

func (f *fixture) callback(state, code string) *http.Response {
	f.t.Helper()
	target := f.server.URL + "/login/oidc/" + testProviderName + "/callback?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code)
	resp, err := f.client.Get(target)
	if err != nil {
		f.t.Fatalf("GET callback: %v", err)
	}
	f.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (f *fixture) sessionCookie() *http.Cookie {
	f.t.Helper()
	u, err := url.Parse(f.server.URL)
	if err != nil {
		f.t.Fatalf("parse server URL: %v", err)
	}
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == f.cfg.Session.EffectiveCookieName() {
			return c
		}
	}
	return nil
}

func (f *fixture) stateCookie() *http.Cookie {
	f.t.Helper()
	u, err := url.Parse(f.server.URL)
	if err != nil {
		f.t.Fatalf("parse server URL: %v", err)
	}
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == "passage_oidc" {
			return c
		}
	}
	return nil
}

// assertFailed checks a callback result that must bounce back to /login with a
// flash and must not issue a session.
func (f *fixture) assertFailed(resp *http.Response, wantFlash string) {
	f.t.Helper()
	if resp.StatusCode != http.StatusFound {
		f.t.Fatalf("callback status = %d; want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	want := "/login?flash=" + wantFlash
	if loc != want {
		f.t.Errorf("callback Location = %q; want %q", loc, want)
	}
	if c := f.sessionCookie(); c != nil {
		f.t.Errorf("callback issued a session cookie %q on failure", c.Name)
	}
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(b))
}

func (f *fixture) events(name string) []*authlog.Event {
	f.t.Helper()
	events, err := f.authStore.List(context.Background(), authlog.Filter{Event: name})
	if err != nil {
		f.t.Fatalf("list auth events: %v", err)
	}
	return events
}

func (f *fixture) userCount() int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		f.t.Fatalf("count users: %v", err)
	}
	return n
}

func (f *fixture) challengeCount() int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM mfa_challenges").Scan(&n); err != nil {
		f.t.Fatalf("count mfa challenges: %v", err)
	}
	return n
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// TestCallback_HappyPath_CreatesUserAndSession covers provider discovery, PKCE,
// token exchange, id_token verification, auto-create, linking, and session
// creation.
func TestCallback_HappyPath_CreatesUserAndSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t, true)
	state, _ := f.start("")

	resp := f.callback(state, testCode)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d; want 302 (body: %s)", resp.StatusCode, readBody(resp))
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("callback Location = %q; want /", loc)
	}
	if c := f.sessionCookie(); c == nil || c.Value == "" {
		t.Fatal("no session cookie was issued")
	}
	if f.stateCookie() != nil {
		t.Error("state cookie was not cleared after the callback")
	}
	if got := f.fake.verifier(); got == "" {
		t.Error("token exchange did not send a PKCE code_verifier")
	}

	u, err := f.userSvc.GetByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("created user not found by email: %v", err)
	}
	if u.PasswordHash != "" {
		t.Error("external user has a password hash; want none")
	}
	if !u.EmailVerified {
		t.Error("external user should be email-verified when the provider says so")
	}
	if u.Name != "Alice Example" {
		t.Errorf("user name = %q; want Alice Example", u.Name)
	}

	link, err := f.links.GetBySubject(context.Background(), testProviderName, "subject-alice")
	if err != nil {
		t.Fatalf("link not created: %v", err)
	}
	if link.UserID != u.ID {
		t.Errorf("link user = %q; want %q", link.UserID, u.ID)
	}

	events := f.events(authlog.EventIDPLogin)
	if len(events) != 1 {
		t.Fatalf("idp.login events = %d; want 1", len(events))
	}
	if events[0].UserID != u.ID || events[0].Detail != testProviderName {
		t.Errorf("idp.login event = %+v; want user %q and detail %q", events[0], u.ID, testProviderName)
	}
}

func TestCallback_StateFailures(t *testing.T) {
	t.Parallel()

	t.Run("unknown state", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, true)
		f.start("")
		f.assertFailed(f.callback("not-the-state", testCode), "idp-failed")
		if got := f.fake.calls(); got != 0 {
			t.Errorf("token endpoint called %d times after a state mismatch; want 0", got)
		}
	})

	t.Run("tampered state", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, true)
		state, _ := f.start("")
		f.assertFailed(f.callback(state+"x", testCode), "idp-failed")
		if len(f.events(authlog.EventIDPFailure)) == 0 {
			t.Error("no idp.failure event recorded")
		}
	})

	t.Run("replayed state after the cookie was consumed", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, true)
		state, _ := f.start("")
		first := f.callback(state, testCode)
		if first.StatusCode != http.StatusFound || first.Header.Get("Location") != "/" {
			t.Fatalf("first callback did not succeed: status %d location %q", first.StatusCode, first.Header.Get("Location"))
		}
		if f.stateCookie() != nil {
			t.Fatal("state cookie survived the first callback")
		}
		// The browser no longer holds the single-use state cookie, so the same
		// state cannot be redeemed a second time. A session from the first
		// callback is still in the jar, so only the redirect is checked here.
		replay := f.callback(state, testCode)
		if replay.StatusCode != http.StatusFound {
			t.Fatalf("replay status = %d; want 302", replay.StatusCode)
		}
		if loc := replay.Header.Get("Location"); loc != "/login?flash=idp-failed" {
			t.Errorf("replay Location = %q; want /login?flash=idp-failed", loc)
		}
	})

	t.Run("tampered state cookie", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, true)
		state, _ := f.start("")
		u, err := url.Parse(f.server.URL)
		if err != nil {
			t.Fatalf("parse server URL: %v", err)
		}
		f.client.Jar.SetCookies(u, []*http.Cookie{{Name: "passage_oidc", Value: "not-base64-json"}})
		f.assertFailed(f.callback(state, testCode), "idp-failed")
	})

	t.Run("missing state cookie", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, true)
		f.assertFailed(f.callback("whatever", testCode), "idp-failed")
	})
}

func TestCallback_TokenVerificationFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*fakeProvider, string)
	}{
		{
			name: "nonce mismatch",
			mutate: func(fake *fakeProvider, _ string) {
				fake.setNonce("a-different-nonce")
			},
		},
		{
			name: "wrong issuer",
			mutate: func(fake *fakeProvider, _ string) {
				fake.setClaim("iss", "https://evil.example.com")
			},
		},
		{
			name: "wrong audience",
			mutate: func(fake *fakeProvider, _ string) {
				fake.setClaim("aud", "some-other-client")
			},
		},
		{
			name: "multiple audiences without azp",
			mutate: func(fake *fakeProvider, _ string) {
				fake.setClaim("aud", []string{testClientID, "another-client"})
			},
		},
		{
			name: "expired token",
			mutate: func(fake *fakeProvider, _ string) {
				fake.setClaim("exp", time.Now().Add(-time.Hour).Unix())
			},
		},
		{
			name: "missing expiration",
			mutate: func(fake *fakeProvider, _ string) {
				fake.deleteClaim("exp")
			},
		},
		{
			name: "missing subject",
			mutate: func(fake *fakeProvider, _ string) {
				fake.deleteClaim("sub")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, true)
			state, _ := mustStart(t, f)
			tt.mutate(f.fake, state)
			f.assertFailed(f.callback(state, testCode), "idp-failed")
			if f.userCount() != 0 {
				t.Errorf("users = %d after a rejected token; want 0", f.userCount())
			}
			if len(f.events(authlog.EventIDPFailure)) == 0 {
				t.Error("no idp.failure event recorded")
			}
		})
	}
}

func TestCallback_RejectsUnsignedToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t, true)
	state, nonce := f.start("")
	// A contract-violating provider: unsigned "alg":"none" token carrying the
	// right claims. RS256-only verification must reject it.
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, jwtlib.MapClaims{
		"iss":   f.fake.server.URL,
		"aud":   testClientID,
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"sub":   "subject-alice",
		"nonce": nonce,
	})
	raw, err := tok.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}
	f.fake.setRawIDToken(raw)
	f.assertFailed(f.callback(state, testCode), "idp-failed")
}

func TestCallback_LinksExistingSubject(t *testing.T) {
	t.Parallel()
	f := newFixture(t, false)
	ctx := context.Background()

	existing, err := f.userSvc.Register(ctx, "bob", "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register existing user: %v", err)
	}
	if err := f.links.Create(ctx, &idp.Link{
		UserID:   existing.ID,
		Provider: testProviderName,
		Subject:  "subject-alice",
		Email:    "bob@example.com",
	}); err != nil {
		t.Fatalf("create existing link: %v", err)
	}

	state, _ := f.start("")
	resp := f.callback(state, testCode)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d %q; want 302 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if f.sessionCookie() == nil {
		t.Fatal("no session cookie issued for a linked user")
	}
	if got := f.userCount(); got != 1 {
		t.Errorf("users = %d; want 1 (the existing account)", got)
	}
	if len(f.events(authlog.EventIDPLogin)) != 1 {
		t.Error("no idp.login event")
	}
}

func TestCallback_LinksByVerifiedEmail(t *testing.T) {
	t.Parallel()
	f := newFixture(t, false)
	ctx := context.Background()

	existing, err := f.userSvc.Register(ctx, "alice_user", "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register existing user: %v", err)
	}

	state, _ := f.start("")
	resp := f.callback(state, testCode)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d %q; want 302 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if f.sessionCookie() == nil {
		t.Fatal("no session cookie issued when linking by email")
	}
	link, err := f.links.GetBySubject(ctx, testProviderName, "subject-alice")
	if err != nil {
		t.Fatalf("link not created: %v", err)
	}
	if link.UserID != existing.ID {
		t.Errorf("linked user = %q; want %q", link.UserID, existing.ID)
	}
	if got := f.userCount(); got != 1 {
		t.Errorf("users = %d; want 1", got)
	}
}

func TestCallback_RefusesEmailLinkWhenUnverified(t *testing.T) {
	t.Parallel()
	f := newFixture(t, false)
	ctx := context.Background()

	if _, err := f.userSvc.Register(ctx, "alice_user", "alice@example.com", "password123"); err != nil {
		t.Fatalf("register existing user: %v", err)
	}
	f.fake.setClaim("email_verified", false)

	state, _ := f.start("")
	f.assertFailed(f.callback(state, testCode), "idp-no-account")

	if _, err := f.links.GetBySubject(ctx, testProviderName, "subject-alice"); !errors.Is(err, idp.ErrLinkNotFound) {
		t.Errorf("link lookup = %v; want ErrLinkNotFound (unverified email must not link)", err)
	}
}

func TestCallback_AutoCreatePolicy(t *testing.T) {
	t.Parallel()

	t.Run("auto_create off", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, false)
		state, _ := f.start("")
		f.assertFailed(f.callback(state, testCode), "idp-no-account")
		if got := f.userCount(); got != 0 {
			t.Errorf("users = %d; want 0", got)
		}
	})

	t.Run("auto_create on but registration disabled", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, true)
		f.settings.values["allow_registration"] = "false"
		state, _ := f.start("")
		f.assertFailed(f.callback(state, testCode), "idp-no-account")
		if got := f.userCount(); got != 0 {
			t.Errorf("users = %d; want 0", got)
		}
	})

	t.Run("auto_create on and registration allowed", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, true)
		state, _ := f.start("")
		resp := f.callback(state, testCode)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
			t.Fatalf("callback = %d %q; want 302 /", resp.StatusCode, resp.Header.Get("Location"))
		}
		if got := f.userCount(); got != 1 {
			t.Errorf("users = %d; want 1", got)
		}
	})
}

func TestCallback_UnverifiedEmailCanCreateButNotLink(t *testing.T) {
	t.Parallel()
	f := newFixture(t, true)
	f.fake.setClaim("email_verified", false)

	state, _ := f.start("")
	resp := f.callback(state, testCode)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d %q; want 302 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	u, err := f.userSvc.GetByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("created user not found: %v", err)
	}
	if u.EmailVerified {
		t.Error("new user is email-verified although the provider said false")
	}
}

func TestCallback_InactiveLinkedUser(t *testing.T) {
	t.Parallel()
	f := newFixture(t, false)
	ctx := context.Background()

	existing, err := f.userSvc.Register(ctx, "bob", "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register existing user: %v", err)
	}
	if err := f.links.Create(ctx, &idp.Link{
		UserID:   existing.ID,
		Provider: testProviderName,
		Subject:  "subject-alice",
	}); err != nil {
		t.Fatalf("create link: %v", err)
	}
	existing.IsActive = false
	if err := f.userStore.Update(ctx, existing); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}

	state, _ := f.start("")
	f.assertFailed(f.callback(state, testCode), "account-inactive")
	if len(f.events(authlog.EventIDPFailure)) == 0 {
		t.Error("no idp.failure event recorded")
	}
}

func TestCallback_DoesNotCreateMFAChallenge(t *testing.T) {
	t.Parallel()
	f := newFixture(t, false)
	ctx := context.Background()

	existing, err := f.userSvc.Register(ctx, "bob", "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register existing user: %v", err)
	}
	if err := f.links.Create(ctx, &idp.Link{
		UserID:   existing.ID,
		Provider: testProviderName,
		Subject:  "subject-alice",
	}); err != nil {
		t.Fatalf("create link: %v", err)
	}
	// The account has an enabled second factor. An external sign-in is a
	// primary method, so it must still sign in directly — exactly like a
	// passkey or magic link.
	if _, err := f.db.ExecContext(ctx,
		`INSERT INTO user_mfa (user_id, secret, enabled_at) VALUES (?, 'JBSWY3DPEHPK3PXP', ?)`,
		existing.ID, time.Now().UTC()); err != nil {
		t.Fatalf("enable mfa: %v", err)
	}

	state, _ := f.start("")
	resp := f.callback(state, testCode)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d %q; want 302 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if f.sessionCookie() == nil {
		t.Fatal("no session cookie issued; external sign-in must not be blocked by MFA")
	}
	if got := f.challengeCount(); got != 0 {
		t.Errorf("mfa_challenges rows = %d; want 0", got)
	}
}

func TestCallback_HonoursReturnPath(t *testing.T) {
	t.Parallel()
	f := newFixture(t, true)
	state, _ := f.start("/oauth/authorize?client_id=unknown&state=x")
	resp := f.callback(state, testCode)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d; want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/oauth/authorize?client_id=unknown&state=x" {
		t.Errorf("callback Location = %q; want the safe return path", loc)
	}
}

func TestStart_UnknownProvider(t *testing.T) {
	t.Parallel()
	f := newFixture(t, true)
	resp, err := f.client.Get(f.server.URL + "/login/oidc/nope/start")
	if err != nil {
		t.Fatalf("GET start: %v", err)
	}
	defer resp.Body.Close()
	f.assertFailed(resp, "idp-failed")
}

func TestStart_StripsUnsafeReturnPath(t *testing.T) {
	t.Parallel()
	f := newFixture(t, true)
	state, _ := f.start("//evil.example.com")
	resp := f.callback(state, testCode)
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("callback Location = %q; want / (unsafe rd dropped)", loc)
	}
}

func mustStart(t *testing.T, f *fixture) (string, string) {
	t.Helper()
	state, nonce := f.start("")
	return state, nonce
}
