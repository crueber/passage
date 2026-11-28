package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"strings"
	"sync"
	"syscall"
	"time"

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
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/theme"
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

// magicLinkLockout is how long a client address stays blocked after it burns
// its failed magic-link guesses. The threshold and window come from the admin
// "Magic link" rate limit; this is the floor that makes the throttle worth
// having, so it is deliberately not a setting.
const magicLinkLockout = 24 * time.Hour

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

	// Bind anonymous CSRF tokens (and OIDC state cookies) to a server-side
	// secret even when the operator has not configured one. Ephemeral per
	// process when unset.
	if cfg.CSRF.Key == "" {
		kb := make([]byte, 32)
		if _, err := rand.Read(kb); err != nil {
			return fmt.Errorf("generate csrf key: %w", err)
		}
		cfg.CSRF.Key = hex.EncodeToString(kb)
	}

	logger := buildLogger(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Open the database. Registered before background goroutines and the webhook
	// notifier so LIFO defers stop/drain every goroutine before database.Close().
	database, err := db.Open(ctx, cfg.Database.Path, logger)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

	// Resolve AES-256-GCM key for TOTP secrets and upstream IdP client secrets.
	mfaKey, err := mfa.ResolveKey(cfg.Security.EncryptionKey, cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("resolve mfa encryption key: %w", err)
	}
	mfaCipher, err := mfa.NewCipher(mfaKey)
	if err != nil {
		return fmt.Errorf("init mfa cipher: %w", err)
	}
	clear(mfaKey)

	// Build foundational stores and apply DB-backed feature settings to cfg.
	userStore := user.NewStore(database)
	authStore := authlog.NewStore(database)
	settingsStore := admin.NewSQLiteSettingsStore(database)
	settings.ApplyToConfig(ctx, settingsStore, cfg, logger)

	appStore := app.NewStore(database)
	sessionStore := session.NewStore(database)
	sessionSvc := session.NewService(sessionStore, userStore, settingsStore, &appDurationAdapter{store: appStore}, cfg, logger)

	srvMetrics := newServerMetrics(logger, version, processStart, userStore, appStore, sessionStore)
	sessionSvc.SetSessionCounter(srvMetrics)

	// Security webhook: resolves its configuration per delivery using settings.Raw
	// so clearing URL or secret in the admin UI takes effect immediately.
	webhookConfig := func(ctx context.Context) authlog.WebhookConfig {
		return authlog.WebhookConfig{
			Endpoint: strings.TrimSpace(settings.Raw(ctx, settingsStore, settings.WebhookURL, cfg.Security.WebhookURL)),
			Secret:   settings.Raw(ctx, settingsStore, settings.WebhookSecret, cfg.Security.WebhookSecret),
			Timeout:  time.Duration(settings.Int(ctx, settingsStore, settings.WebhookTimeoutSeconds, cfg.Security.WebhookTimeoutSeconds, 1, 60)) * time.Second,
		}
	}
	notifier, err := authlog.NewWebhookNotifier("", "", 0, logger, webhookConfig)
	if err != nil {
		return fmt.Errorf("configure security webhook: %w", err)
	}
	notifier.Start(ctx)

	var bgWG sync.WaitGroup
	defer func() {
		stop()
		const bgShutdownTimeout = 5 * time.Second
		done := make(chan struct{})
		go func() {
			bgWG.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(bgShutdownTimeout):
			logger.Warn("background tasks did not finish within shutdown timeout", "timeout", bgShutdownTimeout)
		}
		notifier.Close()
	}()

	authRecorder := authlog.NewRecorder(authStore, authEventCounter{counter: srvMetrics.authEvents, next: notifier}, logger)

	userSvc := user.NewService(userStore, userStore, sessionSvc, cfg)
	userSvc.SetSettings(settingsStore)

	mfaStore := mfa.NewStore(database, mfaCipher)
	mfaSvc := mfa.NewService(mfaStore, "Passage", nil)

	mailer, err := email.NewSMTPSender(cfg, logger, settingsStore)
	if err != nil {
		return fmt.Errorf("create email sender: %w", err)
	}

	// Parse HTML templates. csrfField escapes token defensively even though our
	// csrf package emits base64url tokens.
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(token string) template.HTML {
			return template.HTML(`<input type="hidden" name="` + csrfpkg.FieldName + `" value="` + template.HTMLEscapeString(token) + `">`)
		},
		"theme": func(data any) string {
			if v := web.ThemeFromData(data); v != "" {
				return v
			}
			return theme.Canonical(settings.String(context.Background(), settingsStore, settings.Theme, cfg.UI.Theme))
		},
	})
	if err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}

	appSvc := app.NewService(appStore, appStore, logger)

	oauthStore := oauth.NewStore(database)
	oauthSvc, err := oauth.NewService(ctx, oauthStore, appSvc, userStore, cfg.Server.BaseURL, logger)
	if err != nil {
		return fmt.Errorf("init oauth service: %w", err)
	}
	oauthHandler := oauth.NewHandler(oauthSvc, sessionSvc, cfg.Server.BaseURL, authRecorder, cfg, logger)

	credStore := webauthn.NewSQLiteCredentialStore(database)
	challenges := webauthn.NewSQLiteChallengeStore(database, logger)
	wa, err := buildWebAuthn(cfg, logger)
	if err != nil {
		return fmt.Errorf("configure webauthn: %w", err)
	}

	// Rate limiters — in-memory sliding-window, re-applied on settings save.
	rl := cfg.RateLimit
	loginLimiter := ratelimit.New(rl.LoginRequests, time.Duration(rl.LoginWindowMinutes)*time.Minute)
	resetLimiter := ratelimit.New(rl.ResetRequests, time.Duration(rl.ResetWindowMinutes)*time.Minute)
	oauthTokenLimiter := ratelimit.New(rl.OAuthTokenRequests, time.Duration(rl.OAuthTokenWindowMinutes)*time.Minute)
	setupLimiter := ratelimit.New(rl.SetupRequests, time.Duration(rl.SetupWindowMinutes)*time.Minute)
	registerLimiter := ratelimit.New(rl.RegisterRequests, time.Duration(rl.RegisterWindowMinutes)*time.Minute)
	magicLinkLimiter := ratelimit.New(rl.MagicLinkRequests, time.Duration(rl.MagicLinkWindowMinutes)*time.Minute)
	apiLimiter := ratelimit.New(apiRateLimitRequests, apiRateLimitWindow)

	accountThrottle := ratelimit.NewAccountService(ratelimit.NewAccountStore(database), ratelimit.AccountConfig{
		MaxFailures: cfg.Auth.MaxLoginFailures,
		Lockout:     time.Duration(cfg.Auth.LockoutMinutes) * time.Minute,
	}, time.Now)

	magicLinkThrottle := ratelimit.NewMagicLinkService(
		ratelimit.NewMagicLinkStore(database),
		magicLinkThrottleConfig(ctx, settingsStore, cfg),
		time.Now,
	)

	reloadLimiters := func(ctx context.Context) {
		set := func(l *ratelimit.Limiter, requestsKey, windowKey string, fallbackRequests, fallbackWindow int) {
			requests := settings.Int(ctx, settingsStore, requestsKey, fallbackRequests, 0, 100000)
			window := settings.Int(ctx, settingsStore, windowKey, fallbackWindow, 1, 100000)
			l.SetConfig(requests, time.Duration(window)*time.Minute)
		}
		set(loginLimiter, settings.RateLimitLoginRequests, settings.RateLimitLoginWindowMinutes, rl.LoginRequests, rl.LoginWindowMinutes)
		set(resetLimiter, settings.RateLimitResetRequests, settings.RateLimitResetWindowMinutes, rl.ResetRequests, rl.ResetWindowMinutes)
		set(oauthTokenLimiter, settings.RateLimitOAuthTokenRequests, settings.RateLimitOAuthTokenWindowMins, rl.OAuthTokenRequests, rl.OAuthTokenWindowMinutes)
		set(setupLimiter, settings.RateLimitSetupRequests, settings.RateLimitSetupWindowMinutes, rl.SetupRequests, rl.SetupWindowMinutes)
		set(registerLimiter, settings.RateLimitRegisterRequests, settings.RateLimitRegisterWindowMinutes, rl.RegisterRequests, rl.RegisterWindowMinutes)
		set(magicLinkLimiter, settings.RateLimitMagicLinkRequests, settings.RateLimitMagicLinkWindowMinutes, rl.MagicLinkRequests, rl.MagicLinkWindowMinutes)
		accountThrottle.SetConfig(ratelimit.AccountConfig{
			MaxFailures: settings.Int(ctx, settingsStore, settings.MaxLoginFailures, cfg.Auth.MaxLoginFailures, 0, 1000),
			Lockout:     time.Duration(settings.Int(ctx, settingsStore, settings.LockoutMinutes, cfg.Auth.LockoutMinutes, 0, 100000)) * time.Minute,
		})
		magicLinkThrottle.SetConfig(magicLinkThrottleConfig(ctx, settingsStore, cfg))
	}

	startBackgroundTasks(ctx, &bgWG, backgroundDeps{
		mfaStore:          mfaStore,
		mfaSvc:            mfaSvc,
		sessionStore:      sessionStore,
		sessionSvc:        sessionSvc,
		challenges:        challenges,
		oauthStore:        oauthStore,
		authStore:         authStore,
		userSvc:           userSvc,
		accountThrottle:   accountThrottle,
		magicLinkThrottle: magicLinkThrottle,
		limiters: []*ratelimit.Limiter{
			loginLimiter, resetLimiter, oauthTokenLimiter,
			setupLimiter, registerLimiter, magicLinkLimiter, apiLimiter,
		},
	}, logger)

	auditSvc := admin.NewAuditService(admin.NewSQLiteAuditStore(database), logger)
	idpStore := idp.NewProviderStore(database, mfaCipher)

	apiTokenSvc := adminapi.NewService(adminapi.NewStore(database), logger)
	// Pass sessionSvc (not raw sessionStore) so /api/v1/sessions filters idle-expired sessions too.
	apiHandler := adminapi.NewHandler(userStore, appStore, sessionSvc, &auditAPIAdapter{svc: auditSvc}, logger)

	adminHandler := admin.NewHandler(userStore, userSvc, sessionSvc, appSvc, settingsStore, credStore, mfaSvc, mailer, tmpl, cfg, logger, auditSvc, authStore, authRecorder, accountThrottle, apiTokenSvc, oauthSvc)
	adminHandler.SetProviderManager(idpStore)
	adminHandler.SetSettingsReloader(reloadLimiters)

	userHandler := user.NewHandler(userSvc, mfaSvc, appSvc, sessionSvc, settingsStore, mailer, session.UserFromContext, authRecorder, accountThrottle, magicLinkThrottle, tmpl, cfg, logger)
	userHandler.SetProviderSource(idpButtons{store: idpStore})

	idpHandler := idp.NewHandler(
		idp.NewStore(database),
		userSvc,
		appSvc,
		sessionSvc,
		settingsStore,
		authRecorder,
		idp.NewClient(nil),
		idpStore,
		cfg,
		logger,
	)

	faHandler := forwardauth.NewHandler(sessionSvc, appSvc, userHandler, authRecorder, cfg, logger)
	userSessionsHandler := session.NewHandler(sessionSvc, tmpl, cfg, logger)

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
	userHandler.SetSecondFactorPasskey(passkeyHandler)

	staticFS, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		return fmt.Errorf("create static sub-fs: %w", err)
	}

	trustedProxies, err := web.ParseTrustedProxies(cfg.Server.EffectiveTrustedProxies())
	if err != nil {
		return fmt.Errorf("parse server.trusted_proxies: %w", err)
	}

	r := buildRouter(routerDeps{
		cfg:                 cfg,
		logger:              logger,
		staticFS:            staticFS,
		trustedProxies:      trustedProxies,
		settingsStore:       settingsStore,
		srvMetrics:          srvMetrics,
		sessionSvc:          sessionSvc,
		authRecorder:        authRecorder,
		apiTokenSvc:         apiTokenSvc,
		apiHandler:          apiHandler,
		faHandler:           faHandler,
		oauthHandler:        oauthHandler,
		userHandler:         userHandler,
		idpHandler:          idpHandler,
		passkeyHandler:      passkeyHandler,
		userSessionsHandler: userSessionsHandler,
		adminHandler:        adminHandler,
		setupManager:        setupManager,
		loginLimiter:        loginLimiter,
		resetLimiter:        resetLimiter,
		oauthTokenLimiter:   oauthTokenLimiter,
		setupLimiter:        setupLimiter,
		registerLimiter:     registerLimiter,
		magicLinkLimiter:    magicLinkLimiter,
		apiLimiter:          apiLimiter,
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	logger.Info("starting server", "addr", addr, "version", version)

	srvErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

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
// it falls back to localhost on the configured listen port for development.
func buildWebAuthn(cfg *config.Config, logger *slog.Logger) (*gowebauthn.WebAuthn, error) {
	rpID := "localhost"
	port := cfg.Server.Port
	if port <= 0 {
		port = 8080
	}
	rpOrigins := []string{fmt.Sprintf("http://localhost:%d", port)}

	if cfg.Server.BaseURL != "" {
		u, err := url.Parse(cfg.Server.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("parse base_url: %w", err)
		}
		rpID = u.Hostname()
		rpOrigins = []string{u.Scheme + "://" + u.Host}
	}

	logger.Info("webauthn relying party", "rp_id", rpID, "origins", rpOrigins)

	return gowebauthn.New(&gowebauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Passage",
		RPOrigins:     rpOrigins,
	})
}
