package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/adminapi"
	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	csrfpkg "github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/db"
	"github.com/crueber/passage/internal/email"
	"github.com/crueber/passage/internal/forwardauth"
	"github.com/crueber/passage/internal/idp"
	"github.com/crueber/passage/internal/metrics"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
	"github.com/crueber/passage/internal/webauthn"
)

// version is set at build time via -ldflags "-X main.version=1.0.0".
var version = "dev"

// authLogRetention is how long authentication events are kept. It is a
// constant by design: the admin page offers 7/30/90-day windows and nothing
// needs a shorter history.
const authLogRetention = 90 * 24 * time.Hour

// Admin API rate limits. The API is token-authenticated and read-only, so the
// limiter is not a security boundary — it bounds the damage a leaked token or a
// runaway script can do against the single SQLite connection.
const (
	apiRateLimitRequests = 120
	apiRateLimitWindow   = time.Minute
)

// auditAPIAdapter adapts the admin audit service to adminapi.auditSource. The
// admin UI package and the REST API package deliberately do not import each
// other, so the mapping lives here at the wiring layer.
type auditAPIAdapter struct {
	svc *admin.AuditService
}

func (a *auditAPIAdapter) ListAudit(ctx context.Context, limit, offset int) ([]adminapi.AuditRecord, error) {
	events, err := a.svc.List(ctx, admin.AuditFilter{Limit: limit, Offset: offset})
	if err != nil {
		return nil, fmt.Errorf("list audit events for api: %w", err)
	}
	records := make([]adminapi.AuditRecord, len(events))
	for i, e := range events {
		records[i] = adminapi.AuditRecord{
			ID:         e.ID,
			ActorID:    e.ActorID,
			ActorName:  e.ActorName,
			Action:     e.Action,
			TargetType: e.TargetType,
			TargetID:   e.TargetID,
			TargetName: e.TargetName,
			Detail:     e.Detail,
			IPAddress:  e.IPAddress,
			CreatedAt:  e.CreatedAt,
		}
	}
	return records, nil
}

// appDurationAdapter adapts the app store to session.appDurationReader.
// It is unexported and lives at the wiring layer to avoid cross-package coupling.
type appDurationAdapter struct {
	store interface {
		GetByID(ctx context.Context, id string) (*app.App, error)
	}
}

func (a *appDurationAdapter) GetSessionDurationHours(ctx context.Context, appID string) (int, error) {
	ap, err := a.store.GetByID(ctx, appID)
	if err != nil {
		return 0, err
	}
	return ap.SessionDurationHours, nil
}

func run() error {
	// The process start time backs passage_process_start_time_seconds. Capture
	// it before configuration so it reflects process start, not listen time.
	processStart := time.Now()

	// Parse flags.
	configPath := flag.String("config", "passage.yaml", "path to configuration file")
	flag.Parse()

	// Load configuration.
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Bind anonymous CSRF tokens to a server-side secret even when the
	// operator has not configured one (FA-007). Without this, the HMAC
	// signing key is derived solely from the client-held CSRF cookie, so a
	// sibling-subdomain cookie toss yields valid tokens. Ephemeral per
	// process: restarts invalidate outstanding anonymous CSRF cookies, which
	// ProtectAnonymous transparently re-issues.
	if cfg.CSRF.Key == "" {
		kb := make([]byte, 32)
		if _, err := rand.Read(kb); err != nil {
			return fmt.Errorf("generate csrf key: %w", err)
		}
		cfg.CSRF.Key = hex.EncodeToString(kb)
	}

	// Set up logger.
	logger := buildLogger(cfg)

	// Set up top-level context with signal cancellation.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Open the database.
	database, err := db.Open(ctx, cfg.Database.Path, logger)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

	// TOTP secrets are encrypted at rest with AES-256-GCM. The key comes from
	// security.encryption_key when set, otherwise from a 0600 file next to the
	// database (created on first use). Resolving it before anything else fails
	// startup loudly instead of silently leaving enrolled secrets unreadable.
	mfaKey, err := mfa.ResolveKey(cfg.Security.EncryptionKey, cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("resolve mfa encryption key: %w", err)
	}
	mfaCipher, err := mfa.NewCipher(mfaKey)
	if err != nil {
		return fmt.Errorf("init mfa cipher: %w", err)
	}
	// The cipher keeps its own key schedule; drop the raw bytes so they are not
	// sitting in a live slice for the life of the process.
	clear(mfaKey)

	// Build stores and services. The session service is built before the user
	// service so password changes can revoke the user's sessions.
	userStore := user.NewStore(database)

	// Authentication event log. Recording is best-effort: a write failure is
	// logged and never fails the auth flow.
	authStore := authlog.NewStore(database)

	// Build the settings store early so sessionSvc can consult it for
	// the session_duration_hours setting on every new session.
	settingsStore := admin.NewSQLiteSettingsStore(database)

	// Build app store early so sessionSvc can use per-app duration overrides.
	appStore := app.NewStore(database)

	sessionStore := session.NewStore(database)
	sessionSvc := session.NewService(sessionStore, userStore, settingsStore, &appDurationAdapter{store: appStore}, cfg, logger)

	// Prometheus metrics. The registry is built before the auth recorder so
	// every recorded event can be counted, and before sessionSvc starts serving
	// so the session counters are installed from the first sign-in. Gauges are
	// COUNT-query callbacks: a scrape costs three cheap queries and never holds
	// the single SQLite connection across a render.
	srvMetrics := newServerMetrics(logger, version, processStart, userStore, appStore, sessionStore)
	sessionSvc.SetSessionCounter(srvMetrics)

	// Optional security webhook: a second sink on the recorder. An empty URL
	// disables it entirely. The worker runs on the run context; Close stops it
	// deterministically without depending on the parent context being
	// cancelled (early returns, for example).
	var authNotifier authlog.Notifier
	if cfg.Security.WebhookURL != "" {
		notifier, err := authlog.NewWebhookNotifier(
			cfg.Security.WebhookURL,
			cfg.Security.WebhookSecret,
			time.Duration(cfg.Security.WebhookTimeoutSeconds)*time.Second,
			logger,
		)
		if err != nil {
			return fmt.Errorf("configure security webhook: %w", err)
		}
		notifier.Start(ctx)
		defer notifier.Close()
		authNotifier = notifier
	}

	// The metrics counter wraps the webhook sink: every event is counted, then
	// forwarded. Both steps are non-blocking, so a scrape or a dead webhook can
	// never delay a login.
	authRecorder := authlog.NewRecorder(authStore, authEventCounter{counter: srvMetrics.authEvents, next: authNotifier}, logger)

	userSvc := user.NewService(userStore, userStore, sessionSvc, cfg)

	// Two-factor authentication: TOTP secrets, recovery codes, and pending
	// login challenges. Built here so the user handler, the security page, and
	// the admin reset all share one service (and one clock).
	mfaStore := mfa.NewStore(database, mfaCipher)
	mfaSvc := mfa.NewService(mfaStore, "Passage", nil)

	// Rewrite any secret written before encryption existed. Legacy plaintext
	// rows stay readable in the meantime (Decrypt passes them through), so this
	// is a best-effort upgrade: a failure is logged and never fatal, and it runs
	// off the startup path so a large table cannot delay serving.
	go func() {
		n, err := mfaStore.ReencryptSecrets(ctx)
		if err != nil {
			logger.Error("mfa secret re-encryption failed", "error", err)
			return
		}
		if n > 0 {
			logger.Info("encrypted legacy mfa secrets", "count", n)
		}
	}()

	// Build email sender.
	mailer, err := email.NewSMTPSender(cfg, logger)
	if err != nil {
		return fmt.Errorf("create email sender: %w", err)
	}

	// Parse HTML templates, providing the csrfField and theme template functions.
	// csrfField renders a hidden <input> carrying the CSRF token for POST forms.
	// template.HTML is safe here: the value is a base64url-encoded HMAC token
	// with no HTML-special characters, produced entirely by our csrf package.
	//
	// theme renders the configured default theme slug into every page's
	// <html data-theme="...">. html/template escapes it as an attribute value;
	// a per-browser override is applied client-side by static/theme.js.
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(token string) template.HTML {
			return template.HTML(`<input type="hidden" name="` + csrfpkg.FieldName + `" value="` + token + `">`)
		},
		"theme": func() string { return cfg.UI.Theme },
	})
	if err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}

	// Build app service.
	appSvc := app.NewService(appStore, appStore, logger)

	// OIDC signing keys with kid history. EnsureSigningKeys imports the legacy
	// single key from oidc_config on first start (leaving that row in place for
	// a rollback) or generates a key when there is none. The service then loads
	// the keyring; rotation, retirement, and deletion go through it so the
	// JWKS and verification always use the same snapshot.
	oauthStore := oauth.NewStore(database)
	if err := oauthStore.EnsureSigningKeys(ctx); err != nil {
		return fmt.Errorf("init oauth signing keys: %w", err)
	}
	oauthSvc, err := oauth.NewService(ctx, oauthStore, appSvc, userStore, cfg.Server.BaseURL, logger)
	if err != nil {
		return fmt.Errorf("init oauth service: %w", err)
	}
	oauthHandler := oauth.NewHandler(oauthSvc, sessionSvc, cfg.Server.BaseURL, authRecorder, cfg, logger)

	// Build WebAuthn credential store and challenge store.
	credStore := webauthn.NewSQLiteCredentialStore(database)
	challenges := webauthn.NewSQLiteChallengeStore(database, logger)

	// Build the go-webauthn instance from configuration.
	wa, err := buildWebAuthn(cfg, logger)
	if err != nil {
		return fmt.Errorf("configure webauthn: %w", err)
	}

	// Start session cleanup background goroutine.
	// Deletes expired sessions every hour; exits on context cancellation.
	// When an idle timeout is configured, sessions that have gone idle are
	// swept as well so the admin session list does not keep advertising
	// sessions that validation already rejects.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := sessionStore.DeleteExpired(ctx); err != nil {
					logger.Error("session cleanup failed", "error", err)
				}
				if idle := cfg.Session.IdleTimeout(); idle > 0 {
					if err := sessionStore.DeleteIdleBefore(ctx, time.Now().UTC().Add(-idle)); err != nil {
						logger.Error("idle session cleanup failed", "error", err)
					}
				}
			}
		}
	}()

	// Start challenge store cleanup goroutine.
	// Removes expired SQLite WebAuthn challenges every 10 minutes.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := challenges.DeleteExpired(ctx); err != nil {
					logger.Error("webauthn challenge cleanup failed", "error", err)
				}
			}
		}
	}()

	// Start MFA challenge cleanup goroutine.
	// Removes expired second-factor challenges every 10 minutes. Expiry is
	// enforced on read too, so this is housekeeping, not the security boundary.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := mfaSvc.DeleteExpiredChallenges(ctx); err != nil {
					logger.Error("mfa challenge cleanup failed", "error", err)
				}
			}
		}
	}()

	// Start OAuth token/code cleanup goroutine.
	// Removes expired authorization codes, access tokens, and refresh tokens every hour.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := oauthStore.DeleteExpired(ctx); err != nil {
					logger.Error("oauth cleanup failed", "error", err)
				}
			}
		}
	}()

	// Start authentication event retention goroutine.
	// Removes events older than authLogRetention once a day.
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := authStore.PurgeBefore(ctx, time.Now().Add(-authLogRetention)); err != nil {
					logger.Error("auth event retention failed", "error", err)
				}
			}
		}
	}()

	// Rate limiters — in-memory sliding-window, no external dependencies.
	// Limits and window durations are driven by configuration (ratelimit section).
	rl := cfg.RateLimit
	loginLimiter := ratelimit.New(rl.LoginRequests, time.Duration(rl.LoginWindowMinutes)*time.Minute)
	resetLimiter := ratelimit.New(rl.ResetRequests, time.Duration(rl.ResetWindowMinutes)*time.Minute)
	oauthTokenLimiter := ratelimit.New(rl.OAuthTokenRequests, time.Duration(rl.OAuthTokenWindowMinutes)*time.Minute)
	setupLimiter := ratelimit.New(rl.SetupRequests, time.Duration(rl.SetupWindowMinutes)*time.Minute)
	registerLimiter := ratelimit.New(rl.RegisterRequests, time.Duration(rl.RegisterWindowMinutes)*time.Minute)
	magicLinkLimiter := ratelimit.New(rl.MagicLinkRequests, time.Duration(rl.MagicLinkWindowMinutes)*time.Minute)
	apiLimiter := ratelimit.New(apiRateLimitRequests, apiRateLimitWindow)

	// Per-account password-login throttling. SQLite-backed so it survives a
	// restart, unlike the in-memory per-IP limiters above. Both values are
	// validated as non-negative; zero disables the feature.
	accountThrottleStore := ratelimit.NewAccountStore(database)
	accountThrottle := ratelimit.NewAccountService(accountThrottleStore, ratelimit.AccountConfig{
		MaxFailures: cfg.Auth.MaxLoginFailures,
		Lockout:     time.Duration(cfg.Auth.LockoutMinutes) * time.Minute,
	}, time.Now)

	// Start rate limiter cleanup goroutines (every 5 minutes each).
	for _, rl := range []*ratelimit.Limiter{loginLimiter, resetLimiter, oauthTokenLimiter, setupLimiter, registerLimiter, magicLinkLimiter, apiLimiter} {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					rl.Cleanup()
				}
			}
		}()
	}

	// Build admin handler.
	auditStore := admin.NewSQLiteAuditStore(database)
	auditSvc := admin.NewAuditService(auditStore, logger)

	// API tokens for the read-only administrative REST API (/api/v1).
	apiTokenSvc := adminapi.NewService(adminapi.NewStore(database), logger)
	apiHandler := adminapi.NewHandler(userStore, appStore, sessionStore, &auditAPIAdapter{svc: auditSvc}, logger)

	adminHandler := admin.NewHandler(userStore, userSvc, sessionSvc, appSvc, settingsStore, credStore, mfaSvc, mailer, tmpl, cfg, logger, auditSvc, authStore, authRecorder, accountThrottle, apiTokenSvc, oauthSvc)

	// Build user handler.
	userHandler := user.NewHandler(userSvc, mfaSvc, appSvc, sessionSvc, settingsStore, mailer, session.UserFromContext, authRecorder, accountThrottle, tmpl, cfg, logger)

	// Upstream OIDC/OAuth identity providers. With no auth.providers configured
	// the handler has no provider to resolve, so the two routes are inert and
	// sign-in behaves exactly as before.
	idpHandler := idp.NewHandler(
		idp.NewStore(database),
		userSvc,
		appSvc,
		sessionSvc,
		settingsStore,
		authRecorder,
		idp.NewClient(nil),
		cfg,
		logger,
	)

	// Build forward-auth handler. It takes the user handler as its MFA policy
	// gate, so "require MFA" cannot be bypassed by going to an upstream app,
	// and the auth recorder so per-app policy denials reach the security log.
	faHandler := forwardauth.NewHandler(sessionSvc, appSvc, userHandler, authRecorder, cfg, logger)

	// Build the user-facing sessions page handler (self-service revoke).
	userSessionsHandler := session.NewHandler(sessionSvc, tmpl, cfg, logger)

	// If no admin user exists, generate a one-time setup token so the operator
	// can bootstrap the first admin account via /setup. The token is logged to
	// stdout and is valid for 1 hour. The /setup endpoint is disabled once any
	// admin account exists.
	var setupManager *user.SetupTokenManager
	hasAdmin, err := userStore.HasAdmin(ctx)
	if err != nil {
		return fmt.Errorf("check admin existence: %w", err)
	}
	if !hasAdmin {
		mgr, token, err := user.NewSetupTokenManager()
		if err != nil {
			return fmt.Errorf("generate setup token: %w", err)
		}
		setupManager = mgr
		setupURL := cfg.Server.BaseURL + "/setup"
		if cfg.Server.BaseURL == "" {
			setupURL = fmt.Sprintf("http://localhost:%d/setup", cfg.Server.Port)
		}
		logger.Info("═══════════════════════════════════════════════════════")
		logger.Info("  NO ADMIN USER FOUND — INITIAL SETUP REQUIRED")
		logger.Info("  Visit:  " + setupURL)
		logger.Info("  Token:  " + token)
		logger.Info("  Expires in 1 hour. Token is single-use.")
		logger.Info("═══════════════════════════════════════════════════════")
	}

	// Build WebAuthn passkey handler.
	passkeyHandler := webauthn.NewHandler(
		wa,
		credStore,
		challenges,
		userStore,
		sessionSvc,
		cfg.Session.EffectiveCookieName(),
		cfg.Session.CookieSecure,
		tmpl,
		logger,
		settingsStore,
		authRecorder,
		mfaSvc,
	)

	// Let the password flow offer a passkey as the second factor: the WebAuthn
	// handler implements user.secondFactorPasskey. A setter rather than a
	// constructor argument because this handler is built after the user
	// handler, and a nil bridge simply leaves the feature off.
	userHandler.SetSecondFactorPasskey(passkeyHandler)

	// Prepare static file server from embedded FS.
	staticFS, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		return fmt.Errorf("create static sub-fs: %w", err)
	}

	// Build the router.
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	// Request counting sits outside the recoverer so a panicking handler is
	// still counted, at the status the recoverer writes (500).
	r.Use(metrics.HTTPMiddleware(srvMetrics.requests))
	r.Use(middleware.Recoverer)
	r.Use(web.SecurityHeaders())

	// Static assets.
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Health check endpoint.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Status  string `json:"status"`
			Version string `json:"version"`
		}{Status: "ok", Version: version})
	})

	// Prometheus metrics. Registered unconditionally: when metrics.enabled is
	// false the handler answers 404, so the configuration alone decides whether
	// the endpoint exists. Only the method and status of each request are
	// counted — never a path, which would make cardinality unbounded.
	r.Handle("/metrics", srvMetrics.reg.Handler(metrics.HandlerOptions{
		Enabled: cfg.Metrics.Enabled,
		Token:   cfg.Metrics.Token,
	}))

	// Forward-auth endpoints (consumed by reverse proxy).
	faHandler.Routes(r)

	// OAuth 2.0 / OIDC endpoints (public — handler performs its own session checks).
	// Routes are registered explicitly so the rate limiter can be scoped to the
	// token endpoint only; JWKS, discovery, and userinfo are read-only and must
	// not be rate-limited aggressively.
	r.Get("/.well-known/openid-configuration", oauthHandler.Discovery)
	r.Get("/.well-known/jwks.json", oauthHandler.JWKS)
	r.Get("/oauth/authorize", oauthHandler.Authorize)
	r.With(ratelimit.Middleware(oauthTokenLimiter)).Post("/oauth/token", oauthHandler.Token)
	r.Get("/oauth/userinfo", oauthHandler.UserInfo)
	// RP-initiated logout is reached cross-site and is authenticated by the
	// signed id_token_hint, so it takes no CSRF token (see Handler.Logout).
	r.Get("/oauth/logout", oauthHandler.Logout)
	r.Post("/oauth/logout", oauthHandler.Logout)
	r.With(ratelimit.Middleware(oauthTokenLimiter)).Post("/oauth/revoke", oauthHandler.Revoke)
	r.With(ratelimit.Middleware(oauthTokenLimiter)).Post("/oauth/introspect", oauthHandler.Introspect)

	// User-facing auth routes (no session middleware).
	// CSRF protection uses the double-submit cookie pattern for unauthenticated routes.
	r.Group(func(r chi.Router) {
		r.Use(csrfpkg.ProtectAnonymous(cfg.CSRF.Key, cfg.Session.CookieSecure))
		r.Get("/login", userHandler.GetLogin)
		r.With(ratelimit.Middleware(loginLimiter)).Post("/login", userHandler.PostLogin)
		r.Get("/register", userHandler.GetRegister)
		r.With(ratelimit.Middleware(registerLimiter)).Post("/register", userHandler.PostRegister)
		r.Get("/reset", userHandler.GetResetRequest)
		r.With(ratelimit.Middleware(resetLimiter)).Post("/reset", userHandler.PostResetRequest)
		r.Get("/reset/{token}", userHandler.GetResetConfirm)
		r.With(ratelimit.Middleware(resetLimiter)).Post("/reset/{token}", userHandler.PostResetConfirm)
		// Second factor for a password sign-in. The pending challenge is a
		// separate cookie and a separate table — never a session.
		r.Get("/login/mfa", userHandler.GetMFALogin)
		r.With(ratelimit.Middleware(loginLimiter)).Post("/login/mfa", userHandler.PostMFALogin)
		r.Get("/login/magic", userHandler.GetMagicLinkRequest)
		r.Get("/login/magic/verify", userHandler.GetMagicLinkVerify)
		r.With(ratelimit.Middleware(magicLinkLimiter)).Post("/login/magic", userHandler.PostMagicLinkRequest)
		// Upstream identity providers. Both legs are GET; the flow is bound by
		// a single-use state/nonce/PKCE cookie, not a CSRF token.
		idpHandler.Routes(r)
		// Setup endpoint — only active when no admin user exists.
		// The setupManager is nil once an admin account has been created; the
		// handlers check IsActive() on every request so the endpoint self-disables.
		r.Get("/setup", userHandler.GetSetup(setupManager))
		r.With(ratelimit.Middleware(setupLimiter)).Post("/setup", userHandler.PostSetup(setupManager))
	})
	// Logout is a GET that revokes a session cookie — no state-changing CSRF risk.
	r.Get("/logout", userHandler.GetLogout)

	// Email verification links arrive from a mail client: a public GET with no
	// CSRF token. The optional session lookup below only decides where the
	// success flash is shown — it never changes the outcome, and an invalid
	// session is simply ignored.
	r.With(ratelimit.Middleware(magicLinkLimiter)).Get("/verify-email/{token}", func(w http.ResponseWriter, req *http.Request) {
		if c, err := req.Cookie(cfg.Session.EffectiveCookieName()); err == nil && c.Value != "" {
			if _, u, err := sessionSvc.ValidateSession(req.Context(), c.Value); err == nil {
				req = req.WithContext(session.WithUser(req.Context(), u))
			}
		}
		userHandler.GetVerifyEmail(w, req)
	})

	// Passkey login routes (public — no session required).
	// These are JSON API endpoints driven by passkey.js — no CSRF token needed
	// because the browser WebAuthn API does not submit cross-origin credentials.
	passkeyHandler.AuthRoutes(r)

	// Passkey as the second factor of a password sign-in. Registered outside the
	// ProtectAnonymous group for the same reason as the passkey login routes:
	// passkey.js cannot produce a CSRF token, and the request is authenticated
	// by the SameSite=Lax, HttpOnly pending-challenge cookie instead. These
	// endpoints verify an assertion against a live challenge; they never create
	// a session on their own.
	r.With(ratelimit.Middleware(loginLimiter)).Post("/login/mfa/passkey/begin", userHandler.PostMFAPasskeyBegin)
	r.With(ratelimit.Middleware(loginLimiter)).Post("/login/mfa/passkey/finish", userHandler.PostMFAPasskeyFinish)

	// Administrative REST API — read-only, authenticated by a bearer token
	// minted from /admin/api-tokens rather than by a session cookie, so it sits
	// outside every session/CSRF group. There are no mutation endpoints.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(ratelimit.Middleware(apiLimiter))
		r.Use(adminapi.RequireToken(apiTokenSvc, authRecorder, logger))
		apiHandler.Routes(r)
	})

	// Protected routes require a valid session.
	// CSRF protection is session-bound for authenticated routes.
	r.Group(func(r chi.Router) {
		r.Use(session.RequireSession(sessionSvc, cfg))
		r.Use(csrfpkg.ProtectAuthenticated(cfg.Session.EffectiveCookieName()))

		// MFA enrollment/management and the Security page are reachable even
		// while the global "require MFA" policy is on: they are the routes a
		// user needs in order to satisfy it. /logout and /static/* are outside
		// this group entirely.
		userHandler.MFARoutes(r, loginLimiter)
		passkeyHandler.ProfileRoutes(r)

		// Everything else is behind the policy gate.
		r.Group(func(r chi.Router) {
			r.Use(userHandler.RequireMFA)
			r.Get("/", userHandler.GetDashboard)
			r.With(ratelimit.Middleware(magicLinkLimiter)).Post("/verify-email/resend", userHandler.PostVerifyEmailResend)

			// Self-service session management (list, revoke one, sign out
			// everywhere). All routes are scoped to the current user.
			userSessionsHandler.Routes(r)
		})
	})

	// Admin routes — protected by RequireAdmin middleware.
	r.Route("/admin", func(r chi.Router) {
		r.Use(admin.RequireAdmin(sessionSvc, cfg))
		r.Use(csrfpkg.ProtectAuthenticated(cfg.Session.EffectiveCookieName()))
		// The global MFA policy applies to the admin UI too. An admin who has
		// not enrolled is sent to /mfa/setup, which lives outside /admin.
		r.Use(userHandler.RequireMFA)
		adminHandler.Routes(r)
	})

	// Start the HTTP server.
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	logger.Info("starting server", "addr", addr, "version", version)

	srvErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

	// Wait for shutdown signal or server error.
	select {
	case err := <-srvErr:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
	}
	logger.Info("shutting down server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	logger.Info("server stopped")
	return nil
}

// buildLogger constructs a slog.Logger from the log configuration.
func buildLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Log.Format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// buildWebAuthn constructs a go-webauthn WebAuthn instance from the server configuration.
// The relying party ID is derived from the BaseURL hostname. If BaseURL is not set,
// it falls back to "localhost" for development.
func buildWebAuthn(cfg *config.Config, logger *slog.Logger) (*gowebauthn.WebAuthn, error) {
	rpID := "localhost"
	rpOrigins := []string{"http://localhost:8080"}

	if cfg.Server.BaseURL != "" {
		u, err := url.Parse(cfg.Server.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("parse base_url: %w", err)
		}
		rpID = u.Hostname()
		rpOrigins = []string{cfg.Server.BaseURL}
	}

	// The RP ID must be the site's registrable domain and the origin must match
	// exactly, or the browser will not offer a registered passkey. Logging both
	// makes that class of failure diagnosable without a debugger.
	logger.Info("webauthn relying party", "rp_id", rpID, "origins", rpOrigins)

	return gowebauthn.New(&gowebauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Passage",
		RPOrigins:     rpOrigins,
	})
}
