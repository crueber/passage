package main

import (
	"bytes"
	"context"
	"crypto/rsa"
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
	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
	csrfpkg "github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/db"
	"github.com/crueber/passage/internal/email"
	"github.com/crueber/passage/internal/forwardauth"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
	"github.com/crueber/passage/internal/webauthn"
)

// version is set at build time via -ldflags "-X main.version=1.0.0".
var version = "dev"

func run() error {
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

	// Build stores and services.
	userStore := user.NewStore(database)
	userSvc := user.NewService(userStore, userStore, cfg)

	// Build the settings store early so sessionSvc can consult it for
	// the session_duration_hours setting on every new session.
	settingsStore := admin.NewSQLiteSettingsStore(database)

	sessionStore := session.NewStore(database)
	sessionSvc := session.NewService(sessionStore, userStore, settingsStore, cfg, logger)

	// Build email sender.
	mailer, err := email.NewSMTPSender(cfg, logger)
	if err != nil {
		return fmt.Errorf("create email sender: %w", err)
	}

	// Parse HTML templates, providing the csrfField template function.
	// csrfField renders a hidden <input> carrying the CSRF token for POST forms.
	// template.HTML is safe here: the value is a base64url-encoded HMAC token
	// with no HTML-special characters, produced entirely by our csrf package.
	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(token string) template.HTML {
			return template.HTML(`<input type="hidden" name="` + csrfpkg.FieldName + `" value="` + token + `">`)
		},
	})
	if err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}

	// Build app store and service.
	appStore := app.NewStore(database)
	appSvc := app.NewService(appStore, appStore, logger)

	// Load or generate the OIDC RSA signing key.
	oauthStore := oauth.NewStore(database)
	oauthKeyPEM, oauthKID, err := oauthStore.GetOrCreateRSAKey(ctx)
	if err != nil {
		return fmt.Errorf("init oauth signing key: %w", err)
	}
	oauthSvc, err := oauth.NewService(oauthStore, appStore, userStore, oauthKeyPEM, oauthKID, cfg.Server.BaseURL, logger)
	if err != nil {
		return fmt.Errorf("init oauth service: %w", err)
	}
	oauthHandler := oauth.NewHandler(oauthSvc, sessionSvc, oauthSvc.PrivateKey().Public().(*rsa.PublicKey), oauthSvc.KeyID(), cfg.Server.BaseURL, cfg.Session.CookieName, logger)

	// Build WebAuthn credential store and challenge store.
	credStore := webauthn.NewSQLiteCredentialStore(database)
	challenges := webauthn.NewSQLiteChallengeStore(database, logger)

	// Build the go-webauthn instance from configuration.
	wa, err := buildWebAuthn(cfg)
	if err != nil {
		return fmt.Errorf("configure webauthn: %w", err)
	}

	// Start session cleanup background goroutine.
	// Deletes expired sessions every hour; exits on context cancellation.
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

	// Rate limiters — in-memory sliding-window, no external dependencies.
	// Limits and window durations are driven by configuration (ratelimit section).
	rl := cfg.RateLimit
	loginLimiter := ratelimit.New(rl.LoginRequests, time.Duration(rl.LoginWindowMinutes)*time.Minute)
	resetLimiter := ratelimit.New(rl.ResetRequests, time.Duration(rl.ResetWindowMinutes)*time.Minute)
	oauthTokenLimiter := ratelimit.New(rl.OAuthTokenRequests, time.Duration(rl.OAuthTokenWindowMinutes)*time.Minute)
	setupLimiter := ratelimit.New(rl.SetupRequests, time.Duration(rl.SetupWindowMinutes)*time.Minute)

	// Start rate limiter cleanup goroutines (every 5 minutes each).
	for _, rl := range []*ratelimit.Limiter{loginLimiter, resetLimiter, oauthTokenLimiter, setupLimiter} {
		rl := rl // capture loop variable
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
	adminHandler := admin.NewHandler(userStore, userSvc, sessionSvc, appSvc, settingsStore, credStore, mailer, tmpl, cfg, logger, auditSvc)

	// Build forward-auth handler.
	faHandler := forwardauth.NewHandler(sessionSvc, appSvc, cfg, logger)

	// Build user handler.
	userHandler := user.NewHandler(userSvc, sessionSvc, settingsStore, mailer, tmpl, cfg, logger)

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
		cfg.Session.CookieName,
		cfg.Session.CookieSecure,
		tmpl,
		logger,
	)

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

	// User-facing auth routes (no session middleware).
	// CSRF protection uses the double-submit cookie pattern for unauthenticated routes.
	r.Group(func(r chi.Router) {
		r.Use(csrfpkg.ProtectAnonymous(cfg.CSRF.Key, cfg.Session.CookieSecure))
		r.Get("/login", userHandler.GetLogin)
		r.With(ratelimit.Middleware(loginLimiter)).Post("/login", userHandler.PostLogin)
		r.Get("/register", userHandler.GetRegister)
		r.Post("/register", userHandler.PostRegister)
		r.Get("/reset", userHandler.GetResetRequest)
		r.With(ratelimit.Middleware(resetLimiter)).Post("/reset", userHandler.PostResetRequest)
		r.Get("/reset/{token}", userHandler.GetResetConfirm)
		r.With(ratelimit.Middleware(resetLimiter)).Post("/reset/{token}", userHandler.PostResetConfirm)
		// Setup endpoint — only active when no admin user exists.
		// The setupManager is nil once an admin account has been created; the
		// handlers check IsActive() on every request so the endpoint self-disables.
		r.Get("/setup", userHandler.GetSetup(setupManager))
		r.With(ratelimit.Middleware(setupLimiter)).Post("/setup", userHandler.PostSetup(setupManager))
	})
	// Logout is a GET that revokes a session cookie — no state-changing CSRF risk.
	r.Get("/logout", userHandler.GetLogout)

	// Passkey login routes (public — no session required).
	// These are JSON API endpoints driven by passkey.js — no CSRF token needed
	// because the browser WebAuthn API does not submit cross-origin credentials.
	passkeyHandler.AuthRoutes(r)

	// Protected routes require a valid session.
	// CSRF protection is session-bound for authenticated routes.
	r.Group(func(r chi.Router) {
		r.Use(session.RequireSession(sessionSvc, cfg))
		r.Use(csrfpkg.ProtectAuthenticated(cfg.Session.CookieName))
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			u, _ := session.UserFromContext(r.Context())
			if u != nil && u.IsAdmin {
				http.Redirect(w, r, "/admin", http.StatusFound)
				return
			}

			ctx := r.Context()
			var apps []*app.App
			if u != nil {
				var err error
				apps, err = appSvc.ListAppsForUser(ctx, u.ID)
				if err != nil {
					logger.Error("dashboard: list apps for user", "user_id", u.ID, "error", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}

			type dashboardData struct {
				User *user.User
				Apps []*app.App
			}

			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, "user-dashboard", dashboardData{
				User: u,
				Apps: apps,
			}); err != nil {
				logger.Error("dashboard: render template", "error", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = buf.WriteTo(w)
		})

		// Passkey management routes (require session).
		passkeyHandler.ProfileRoutes(r)
	})

	// Admin routes — protected by RequireAdmin middleware.
	r.Route("/admin", func(r chi.Router) {
		r.Use(admin.RequireAdmin(sessionSvc, cfg))
		r.Use(csrfpkg.ProtectAuthenticated(cfg.Session.CookieName))
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
func buildWebAuthn(cfg *config.Config) (*gowebauthn.WebAuthn, error) {
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

	return gowebauthn.New(&gowebauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Passage",
		RPOrigins:     rpOrigins,
	})
}
