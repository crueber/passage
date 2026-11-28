package main

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/adminapi"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	csrfpkg "github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/forwardauth"
	"github.com/crueber/passage/internal/idp"
	"github.com/crueber/passage/internal/metrics"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/web"
	"github.com/crueber/passage/internal/webauthn"
)

// routerDeps groups all handlers, middleware dependencies, and rate limiters
// mounted onto the HTTP router.
type routerDeps struct {
	cfg                 *config.Config
	logger              *slog.Logger
	staticFS            fs.FS
	trustedProxies      []netip.Prefix
	settingsStore       settings.Store
	srvMetrics          *serverMetrics
	sessionSvc          *session.Service
	authRecorder        *authlog.Recorder
	apiTokenSvc         *adminapi.Service
	apiHandler          *adminapi.Handler
	faHandler           *forwardauth.Handler
	oauthHandler        *oauth.Handler
	userHandler         *user.Handler
	idpHandler          *idp.Handler
	passkeyHandler      *webauthn.Handler
	userSessionsHandler *session.Handler
	adminHandler        *admin.Handler
	setupManager        *user.SetupTokenManager

	loginLimiter      *ratelimit.Limiter
	resetLimiter      *ratelimit.Limiter
	oauthTokenLimiter *ratelimit.Limiter
	setupLimiter      *ratelimit.Limiter
	registerLimiter   *ratelimit.Limiter
	magicLinkLimiter  *ratelimit.Limiter
	apiLimiter        *ratelimit.Limiter
}

// buildRouter wires every route group, middleware chain, and rate limiter.
func buildRouter(d routerDeps) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(web.TrustedRealIP(d.trustedProxies))
	r.Use(web.RequestLogger(d.logger))
	// Request counting sits outside the recoverer so a panicking handler is
	// still counted, at the status the recoverer writes (500).
	r.Use(metrics.HTTPMiddleware(d.srvMetrics.requests))
	r.Use(middleware.Recoverer)
	r.Use(web.SecurityHeaders())

	// Static assets with strong ETag + Cache-Control revalidation.
	r.Handle("/static/*", http.StripPrefix("/static/", web.StaticHandler(d.staticFS)))

	// Health check endpoint.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Status  string `json:"status"`
			Version string `json:"version"`
		}{Status: "ok", Version: version})
	})

	// Prometheus metrics. Registered unconditionally: when metrics.enabled is
	// false the handler answers 404, so the configuration alone decides whether
	// the endpoint exists. Read per request so Settings → Security applies live.
	r.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		d.srvMetrics.reg.Handler(metrics.HandlerOptions{
			Enabled: settings.Bool(req.Context(), d.settingsStore, settings.MetricsEnabled, d.cfg.Metrics.Enabled),
			Token:   strings.TrimSpace(settings.Raw(req.Context(), d.settingsStore, settings.MetricsToken, d.cfg.Metrics.Token)),
		}).ServeHTTP(w, req)
	}))

	// Forward-auth endpoints (consumed by reverse proxy).
	d.faHandler.Routes(r)

	// OAuth 2.0 / OIDC endpoints (public — handler performs its own session checks).
	// Read-only discovery/JWKS/userinfo are deliberately not rate-limited.
	r.Get("/.well-known/openid-configuration", d.oauthHandler.Discovery)
	r.Get("/.well-known/jwks.json", d.oauthHandler.JWKS)
	r.Get("/oauth/authorize", d.oauthHandler.Authorize)
	r.With(ratelimit.Middleware(d.oauthTokenLimiter)).Post("/oauth/token", d.oauthHandler.Token)
	r.Get("/oauth/userinfo", d.oauthHandler.UserInfo)
	// RP-initiated logout is reached cross-site and is authenticated by the
	// signed id_token_hint, so it takes no CSRF token (see Handler.Logout).
	r.Get("/oauth/logout", d.oauthHandler.Logout)
	r.Post("/oauth/logout", d.oauthHandler.Logout)
	r.With(ratelimit.Middleware(d.oauthTokenLimiter)).Post("/oauth/revoke", d.oauthHandler.Revoke)
	r.With(ratelimit.Middleware(d.oauthTokenLimiter)).Post("/oauth/introspect", d.oauthHandler.Introspect)

	// Upstream identity providers. Both legs are GET; the flow is bound by a
	// signed single-use state/nonce/PKCE cookie, not a CSRF token.
	d.idpHandler.Routes(r)

	// User-facing anonymous form routes (double-submit CSRF cookie).
	r.Group(func(r chi.Router) {
		r.Use(csrfpkg.ProtectAnonymous(d.cfg.CSRF.Key, d.cfg.Session.CookieSecure))
		r.Get("/login", d.userHandler.GetLogin)
		r.With(ratelimit.Middleware(d.loginLimiter)).Post("/login", d.userHandler.PostLogin)
		r.Get("/register", d.userHandler.GetRegister)
		r.With(ratelimit.Middleware(d.registerLimiter)).Post("/register", d.userHandler.PostRegister)
		r.Get("/invite/{token}", d.userHandler.GetInviteAccept)
		r.With(ratelimit.Middleware(d.registerLimiter)).Post("/invite/{token}", d.userHandler.PostInviteAccept)
		r.Get("/reset", d.userHandler.GetResetRequest)
		r.With(ratelimit.Middleware(d.resetLimiter)).Post("/reset", d.userHandler.PostResetRequest)
		r.Get("/reset/{token}", d.userHandler.GetResetConfirm)
		r.With(ratelimit.Middleware(d.resetLimiter)).Post("/reset/{token}", d.userHandler.PostResetConfirm)
		r.Get("/login/mfa", d.userHandler.GetMFALogin)
		r.With(ratelimit.Middleware(d.loginLimiter)).Post("/login/mfa", d.userHandler.PostMFALogin)
		r.Get("/login/magic", d.userHandler.GetMagicLinkRequest)
		r.Get("/login/magic/verify", d.userHandler.GetMagicLinkVerify)
		r.With(ratelimit.Middleware(d.magicLinkLimiter)).Post("/login/magic", d.userHandler.PostMagicLinkRequest)
		r.Get("/setup", d.userHandler.GetSetup(d.setupManager))
		r.With(ratelimit.Middleware(d.setupLimiter)).Post("/setup", d.userHandler.PostSetup(d.setupManager))
	})

	// Logout is a GET that revokes a session cookie — no state-changing CSRF risk.
	r.Get("/logout", d.userHandler.GetLogout)

	// Email verification links arrive from a mail client: a public GET with no
	// CSRF token. Optional session lookup only decides where the flash renders.
	r.With(ratelimit.Middleware(d.magicLinkLimiter)).Get("/verify-email/{token}", func(w http.ResponseWriter, req *http.Request) {
		if c, err := req.Cookie(d.cfg.Session.EffectiveCookieName()); err == nil && c.Value != "" {
			if _, u, err := d.sessionSvc.ValidateSession(req.Context(), c.Value); err == nil {
				req = req.WithContext(session.WithUser(req.Context(), u))
			}
		}
		d.userHandler.GetVerifyEmail(w, req)
	})

	// Passkey login routes (JSON API driven by passkey.js, rate-limited by loginLimiter).
	d.passkeyHandler.AuthRoutes(r, d.loginLimiter)

	// Passkey as the second factor of a password sign-in, authenticated by the
	// SameSite=Lax HttpOnly pending-challenge cookie.
	r.With(ratelimit.Middleware(d.loginLimiter)).Post("/login/mfa/passkey/begin", d.userHandler.PostMFAPasskeyBegin)
	r.With(ratelimit.Middleware(d.loginLimiter)).Post("/login/mfa/passkey/finish", d.userHandler.PostMFAPasskeyFinish)

	// Administrative REST API — read-only, bearer-token authenticated.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(ratelimit.Middleware(d.apiLimiter))
		r.Use(adminapi.RequireToken(d.apiTokenSvc, d.authRecorder, d.logger))
		d.apiHandler.Routes(r)
	})

	// Protected user routes (session + session-bound CSRF).
	r.Group(func(r chi.Router) {
		r.Use(session.RequireSession(d.sessionSvc, d.cfg))
		r.Use(csrfpkg.ProtectAuthenticated(d.cfg.Session.EffectiveCookieName()))

		// Reachable even while global "require MFA" policy is on so users can enrol.
		d.userHandler.MFARoutes(r, d.loginLimiter)
		d.passkeyHandler.ProfileRoutes(r)
		r.Get("/profile", d.userHandler.GetProfile)
		r.Post("/profile", d.userHandler.PostUpdateProfile)
		r.With(ratelimit.Middleware(d.loginLimiter)).Post("/password", d.userHandler.PostChangePassword)

		// Behind the MFA policy gate.
		r.Group(func(r chi.Router) {
			r.Use(d.userHandler.RequireMFA)
			r.Get("/", d.userHandler.GetDashboard)
			r.Post("/apps/{id}/favorite", d.userHandler.PostToggleFavorite)
			r.With(ratelimit.Middleware(d.magicLinkLimiter)).Post("/verify-email/resend", d.userHandler.PostVerifyEmailResend)
			d.userSessionsHandler.Routes(r)
		})
	})

	// Admin routes — protected by RequireAdmin, session-bound CSRF, and MFA policy.
	r.Route("/admin", func(r chi.Router) {
		r.Use(admin.RequireAdmin(d.sessionSvc, d.cfg))
		r.Use(csrfpkg.ProtectAuthenticated(d.cfg.Session.EffectiveCookieName()))
		r.Use(d.userHandler.RequireMFA)
		d.adminHandler.Routes(r)
	})

	return r
}
