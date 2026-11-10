package user_test

import (
	"context"
	"database/sql"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/theme"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
)

// appStoreDuration adapts the app store to session.appDurationReader, mirroring
// the adapter cmd/passage wires in production.
type appStoreDuration struct {
	store *app.SQLiteStore
}

func (a appStoreDuration) GetSessionDurationHours(ctx context.Context, appID string) (int, error) {
	ap, err := a.store.GetByID(ctx, appID)
	if err != nil {
		return 0, err
	}
	return ap.SessionDurationHours, nil
}

// loginFixture builds a user handler whose session service resolves per-app
// durations, so tests can prove the resolved appID reaches CreateSession.
type loginFixture struct {
	db      *sql.DB
	handler *user.Handler
	appSvc  *app.Service
	cfg     *config.Config
	user    *user.User
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()

	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := &config.Config{
		Auth: config.AuthConfig{AllowRegistration: true, BcryptCost: 10},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
	}
	userSvc := user.NewService(userStore, userStore, nil, cfg)

	appStore := app.NewStore(db)
	appSvc := app.NewService(appStore, appStore, slog.Default())

	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, appStoreDuration{store: appStore}, cfg, slog.Default())

	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     func() string { return theme.Default() },
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	handler := user.NewHandler(userSvc, appSvc, sessionSvc, noopSettings{}, noopSender{}, session.UserFromContext, tmpl, cfg, logger)

	u, err := userSvc.Register(context.Background(), "login_user", "login@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	return &loginFixture{db: db, handler: handler, appSvc: appSvc, cfg: cfg, user: u}
}

// createOAuthApp inserts an app with OAuth credentials and an optional session
// duration override, returning it.
func (f *loginFixture) createOAuthApp(t *testing.T, clientID string, durationHours int) *app.App {
	t.Helper()
	a := &app.App{
		Slug:                 "oauth-" + clientID,
		Name:                 "OAuth App " + clientID,
		HostPattern:          clientID + ".example.com",
		IsActive:             true,
		SessionDurationHours: durationHours,
		ClientID:             clientID,
		ClientSecretHash:     "hash",
		OAuthEnabled:         true,
	}
	if err := f.appSvc.Create(context.Background(), a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	return a
}

// newSessionID extracts the session token from the login response cookie.
func newSessionID(t *testing.T, res *http.Response, cookieName string) string {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name == cookieName && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("response did not set a non-empty %q cookie", cookieName)
	return ""
}

// storedSession reads the app_id and expiry of the session with the given token.
func storedSession(t *testing.T, db *sql.DB, token string) (appID sql.NullString, expiresAt time.Time) {
	t.Helper()
	err := db.QueryRowContext(context.Background(),
		`SELECT app_id, expires_at FROM sessions WHERE id = ?`, token,
	).Scan(&appID, &expiresAt)
	if err != nil {
		t.Fatalf("query session: %v", err)
	}
	return appID, expiresAt
}

// TestPostLogin_ResolvesAppFromOAuthReturnTarget verifies that a login for an
// OAuth client creates a session scoped to that app, so the app's session
// duration override actually applies. It exercises both channels a return
// target arrives on: the passage_rd cookie set by /auth/start (the real proxy
// flow) and the rd form field (a direct /login?rd=… visit).
func TestPostLogin_ResolvesAppFromOAuthReturnTarget(t *testing.T) {
	t.Parallel()

	authorizePath := "/oauth/authorize?client_id=client-abc&response_type=code&redirect_uri=" +
		url.QueryEscape("https://app.example.com/callback")

	cases := []struct {
		name      string
		formRd    string
		cookieRd  string
		extraApps bool
	}{
		{name: "rd form field", formRd: authorizePath},
		{name: "passage_rd cookie from /auth/start", cookieRd: authorizePath},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newLoginFixture(t)
			a := f.createOAuthApp(t, "client-abc", 1) // 1-hour override vs 24h global

			form := url.Values{}
			form.Set("username", "login_user")
			form.Set("password", "password123")
			if tc.formRd != "" {
				form.Set("rd", tc.formRd)
			}

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.cookieRd != "" {
				req.AddCookie(&http.Cookie{Name: "passage_rd", Value: tc.cookieRd})
			}
			rec := httptest.NewRecorder()
			f.handler.PostLogin(rec, req)

			res := rec.Result()
			if res.StatusCode != http.StatusFound {
				t.Fatalf("PostLogin: got status %d, want 302", res.StatusCode)
			}
			if loc := res.Header.Get("Location"); loc != authorizePath {
				t.Errorf("redirect target = %q, want %q", loc, authorizePath)
			}

			token := newSessionID(t, res, f.cfg.Session.EffectiveCookieName())
			appID, expiresAt := storedSession(t, f.db, token)

			if !appID.Valid || appID.String != a.ID {
				t.Errorf("session app_id = %v, want %q", appID, a.ID)
			}
			want := time.Now().Add(time.Hour)
			if diff := expiresAt.Sub(want); diff < -5*time.Minute || diff > 5*time.Minute {
				t.Errorf("session expiry = %v, want ~1h from now (%v)", expiresAt, want)
			}
		})
	}
}

// TestPostLogin_WithoutAppUsesGlobalDuration verifies that logins that cannot
// name an app (bare /login, an unknown OAuth client) keep app_id NULL and get
// the global duration.
func TestPostLogin_WithoutAppUsesGlobalDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		rd   string
	}{
		{name: "bare login", rd: ""},
		{name: "non-oauth return target", rd: "/admin"},
		{name: "unknown oauth client", rd: "/oauth/authorize?client_id=does-not-exist&response_type=code"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newLoginFixture(t)
			f.createOAuthApp(t, "client-abc", 1)

			form := url.Values{}
			form.Set("username", "login_user")
			form.Set("password", "password123")
			if tc.rd != "" {
				form.Set("rd", tc.rd)
			}

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			f.handler.PostLogin(rec, req)

			res := rec.Result()
			if res.StatusCode != http.StatusFound {
				t.Fatalf("PostLogin: got status %d, want 302", res.StatusCode)
			}

			token := newSessionID(t, res, f.cfg.Session.EffectiveCookieName())
			appID, expiresAt := storedSession(t, f.db, token)

			if appID.Valid {
				t.Errorf("session app_id = %q, want NULL", appID.String)
			}
			want := time.Now().Add(24 * time.Hour)
			if diff := expiresAt.Sub(want); diff < -5*time.Minute || diff > 5*time.Minute {
				t.Errorf("session expiry = %v, want ~24h from now (%v)", expiresAt, want)
			}
		})
	}
}
