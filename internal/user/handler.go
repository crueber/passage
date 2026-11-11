package user

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/email"
	"github.com/crueber/passage/internal/ratelimit"
)

// Flash represents a flash message rendered above a form.
type Flash struct {
	Type    string // "error", "success", or "info"
	Message string
}

// sessionCreator is the interface the Handler uses to create and revoke
// sessions. Defined here at the consumer boundary to break the import cycle
// (session imports user; user cannot import session).
//
// NewSession returns the session token string and its expiry time so the
// handler can set the cookie without needing to import the session package.
type sessionCreator interface {
	CreateSession(ctx context.Context, userID string, appID *string, ip, ua string) (token string, expiresAt time.Time, err error)
	RevokeSession(ctx context.Context, token string) error
}

// settingsReader is the minimal interface for reading site settings.
// Defined at the consumer boundary (user package) to avoid import cycles.
type settingsReader interface {
	Get(ctx context.Context, key string) (string, error)
}

// AppLister provides the app lookups the handler needs: the apps a user can
// access (dashboard) and the app that owns an OAuth client_id (used to resolve
// a per-app session duration from an OAuth login return target). Defined at
// the consumer boundary; backed by *app.Service in run.go.
type AppLister interface {
	ListAppsForUser(ctx context.Context, userID string) ([]*app.App, error)
	GetByClientID(ctx context.Context, clientID string) (*app.App, error)
}

// userContextReader extracts the authenticated user from the request context.
// Defined at the consumer boundary because the session package imports user;
// run.go wires session.UserFromContext in.
type userContextReader func(ctx context.Context) (*User, bool)

// authEventRecorder records authentication events for the admin security log.
// Defined at the consumer boundary; backed by *authlog.Recorder in run.go.
// Recording is best-effort: the Recorder never returns an error.
type authEventRecorder interface {
	Record(ctx context.Context, e authlog.Event)
}

// loginThrottle is the per-account password-login throttle.
// Defined at the consumer boundary; backed by *ratelimit.AccountService in run.go.
// Checks and writes are best-effort: an error is logged and the login proceeds
// so a database problem can never lock an operator out.
type loginThrottle interface {
	Status(ctx context.Context, username string) (ratelimit.AccountStatus, error)
	RecordFailure(ctx context.Context, username string) (ratelimit.AccountStatus, error)
	Reset(ctx context.Context, username string) error
}

// Handler handles user-facing HTTP flows: login, register, password reset, logout.
type Handler struct {
	users      *Service
	apps       AppLister
	sessions   sessionCreator
	settings   settingsReader
	mailer     email.Sender
	userCtx    userContextReader
	authEvents authEventRecorder
	throttle   loginThrottle
	tmpl       *template.Template
	cfg        *config.Config
	logger     *slog.Logger
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(
	users *Service,
	apps AppLister,
	sessions sessionCreator,
	settings settingsReader,
	mailer email.Sender,
	userCtx userContextReader,
	authEvents authEventRecorder,
	throttle loginThrottle,
	tmpl *template.Template,
	cfg *config.Config,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		users:      users,
		apps:       apps,
		sessions:   sessions,
		settings:   settings,
		mailer:     mailer,
		userCtx:    userCtx,
		authEvents: authEvents,
		throttle:   throttle,
		tmpl:       tmpl,
		cfg:        cfg,
		logger:     logger,
	}
}

// record emits an authentication event for r, filling in the client address
// and user agent. It is a no-op when no recorder is wired (tests that do not
// exercise the security log).
func (h *Handler) record(r *http.Request, e authlog.Event) {
	if h.authEvents == nil {
		return
	}
	e.IP = authlog.ClientIP(r)
	e.UserAgent = r.UserAgent()
	h.authEvents.Record(r.Context(), e)
}

// registrationAllowed checks the DB setting first, falling back to the static config.
// If the DB setting is present and is "false", registration is disabled.
// If missing (ErrNotFound or any error), fall back to h.cfg.Auth.AllowRegistration.
func (h *Handler) registrationAllowed(ctx context.Context) bool {
	if h.settings == nil {
		return h.cfg.Auth.AllowRegistration
	}
	val, err := h.settings.Get(ctx, "allow_registration")
	if err != nil {
		// Setting not found or DB error — fall back to static config.
		return h.cfg.Auth.AllowRegistration
	}
	return val == "true"
}

// safeReturnPath reports whether rd is a same-site absolute path that is safe
// to redirect to.
//
// It must start with "/" but not "//" (protocol-relative URLs such as
// //evil.example.com are treated as absolute by browsers) and must not contain
// "\" (browsers normalise "\" to "/" in special-scheme URLs, so
// "/\evil.example.com" is equivalent to "//evil.example.com").
func safeReturnPath(rd string) bool {
	return rd != "" && strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//") && !strings.Contains(rd, "\\")
}

// appIDFromReturnTarget returns the app a sign-in is for, when the return
// target identifies one, or nil when it does not.
//
// Only one login flow knows the app: an OAuth client that bounces an
// unauthenticated user to /auth/start (and then /login) sets
// rd=/oauth/authorize?client_id=…, and the client_id names the app exactly.
// Every other flow — a bare /login visit, registration, initial setup, a
// forward-auth bounce (which passes only a path on the Passage host), and
// passkey login (a JSON call with no return target) — carries no app identity,
// so the session gets the global duration. Threading an app hint through
// forward-auth would require changing the proxy contract and is deliberately
// not invented here.
func (h *Handler) appIDFromReturnTarget(ctx context.Context, rd string) *string {
	if rd == "" {
		return nil
	}
	parsed, err := url.Parse(rd)
	if err != nil || parsed.Path != "/oauth/authorize" {
		return nil
	}
	clientID := parsed.Query().Get("client_id")
	if clientID == "" {
		return nil
	}
	a, err := h.apps.GetByClientID(ctx, clientID)
	if err != nil || a == nil {
		// Unknown client (or a DB error): fall back to the global duration
		// rather than failing the login.
		return nil
	}
	return &a.ID
}

// loginData is the template data for the login page.
type loginData struct {
	Flash             *Flash
	RedirectTo        string
	Username          string
	AllowRegistration bool
	AllowPassword     bool
	AllowPasskey      bool
	AllowMagicLink    bool
	CSRFToken         string
}

// registerData is the template data for the register page.
type registerData struct {
	Flash     *Flash
	Username  string
	Email     string
	CSRFToken string
}

// resetRequestData is the template data for the reset request page.
type resetRequestData struct {
	Flash     *Flash
	CSRFToken string
}

// resetConfirmData is the template data for the reset confirmation page.
type resetConfirmData struct {
	Flash     *Flash
	Token     string
	CSRFToken string
}

// dashboardData is the template data for the "My Apps" page.
type dashboardData struct {
	User      *User
	Apps      []*app.App
	Flash     *Flash
	CSRFToken string
}

// GetLogin renders the login form.
func (h *Handler) GetLogin(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	flashMsg := r.URL.Query().Get("flash")
	var flash *Flash
	if flashMsg != "" {
		flash = flashFromCode(flashMsg)
	}

	h.render(w, r, "login.html", loginData{
		Flash:             flash,
		RedirectTo:        rd,
		AllowRegistration: h.registrationAllowed(r.Context()),
		AllowPassword:     isAuthMethodEnabled(r.Context(), h.settings, SettingPasswordEnabled),
		AllowPasskey:      isAuthMethodEnabled(r.Context(), h.settings, SettingPasskeyEnabled),
		AllowMagicLink:    isAuthMethodEnabled(r.Context(), h.settings, SettingMagicLinkEnabled),
		CSRFToken:         csrf.TokenFromContext(r.Context()),
	})
}

// GetDashboard renders the "My Apps" page for the authenticated user.
func (h *Handler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	apps, err := h.apps.ListAppsForUser(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("dashboard: list apps for user", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.render(w, r, "user-dashboard", dashboardData{
		User:      u,
		Apps:      apps,
		Flash:     flashFromCode(r.URL.Query().Get("flash")),
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// PostLogin handles credential submission.
func (h *Handler) PostLogin(w http.ResponseWriter, r *http.Request) {
	if !isAuthMethodEnabled(r.Context(), h.settings, SettingPasswordEnabled) {
		http.Error(w, "Password login is disabled.", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderLoginError(w, r, "Invalid form submission.", r.FormValue("rd"), r.FormValue("username"))
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	rd := r.FormValue("rd")

	// Per-account throttle check runs before password verification. A locked
	// account — real or unknown — gets the same generic page and never reaches
	// bcrypt, so the lock is not an account-existence oracle.
	if h.throttle != nil {
		status, err := h.throttle.Status(r.Context(), username)
		if err != nil {
			// Fail open: a throttle-store problem must not block every login.
			h.logger.Warn("login throttle status", "error", err)
		} else if status.Locked {
			h.record(r, authlog.Event{
				Event:    authlog.EventLoginThrottled,
				Outcome:  authlog.OutcomeThrottled,
				Username: username,
				Detail:   "account locked",
			})
			h.renderLoginError(w, r, lockedLoginMessage(status.Remaining), rd, username)
			return
		}
	}

	u, err := h.users.Authenticate(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserInactive) {
			// Count every rejected credential pair the same way, including
			// unknown usernames. A best-effort failure here must not change the
			// response: the login is already invalid.
			if h.throttle != nil {
				if _, throttleErr := h.throttle.RecordFailure(r.Context(), username); throttleErr != nil {
					h.logger.Warn("login throttle record failure", "error", throttleErr)
				}
			}

			detail := "invalid credentials"
			if errors.Is(err, ErrUserInactive) {
				detail = "account inactive"
			}
			h.record(r, authlog.Event{
				Event:    authlog.EventLoginFailure,
				Outcome:  authlog.OutcomeFailure,
				Username: username,
				Detail:   detail,
			})
			h.renderLoginError(w, r, "Invalid username or password.", rd, username)
			return
		}
		h.logger.Error("authenticate user", "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventLoginFailure,
			Outcome:  authlog.OutcomeFailure,
			Username: username,
			Detail:   "internal error",
		})
		h.renderLoginError(w, r, "An error occurred. Please try again.", rd, username)
		return
	}

	// Correct password: clear any accumulated failures. Best-effort, like the
	// failure path — a store error must not fail a valid login.
	if h.throttle != nil {
		if err := h.throttle.Reset(r.Context(), username); err != nil {
			h.logger.Warn("login throttle reset", "error", err)
		}
	}

	// Resolve the return target first: an OAuth authorization request names the
	// app, and that app may override the session duration. See
	// appIDFromReturnTarget for which flows can and cannot know the app.
	returnTarget := ""
	dest := "/"
	clearReturnCookie := false
	if rdCookie, err := r.Cookie("passage_rd"); err == nil && safeReturnPath(rdCookie.Value) {
		returnTarget = rdCookie.Value
		dest = returnTarget
		clearReturnCookie = true
	} else if safeReturnPath(rd) {
		returnTarget = rd
		dest = rd
	} else if u.IsAdmin {
		// No explicit redirect destination: send admins directly to the admin
		// dashboard rather than the homepage.
		dest = "/admin"
	}

	token, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, h.appIDFromReturnTarget(r.Context(), returnTarget), r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("create session", "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventLoginFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "session create failed",
		})
		h.renderLoginError(w, r, "An error occurred. Please try again.", rd, username)
		return
	}

	setSessionCookie(w, token, expiresAt, h.cfg)
	h.record(r, authlog.Event{
		Event:    authlog.EventLoginSuccess,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   "password",
	})

	if clearReturnCookie {
		// Clear the passage_rd cookie now that we've consumed it.
		http.SetCookie(w, &http.Cookie{
			Name:     "passage_rd",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   h.cfg.Session.CookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// GetRegister renders the registration form.
func (h *Handler) GetRegister(w http.ResponseWriter, r *http.Request) {
	if !h.registrationAllowed(r.Context()) {
		http.Redirect(w, r, "/login?flash=registration-disabled", http.StatusFound)
		return
	}
	h.render(w, r, "register.html", registerData{
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// PostRegister handles registration form submission.
func (h *Handler) PostRegister(w http.ResponseWriter, r *http.Request) {
	if !h.registrationAllowed(r.Context()) {
		http.Redirect(w, r, "/login?flash=registration-disabled", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.render(w, r, "register.html", registerData{
			Flash:     &Flash{Type: "error", Message: "Invalid form submission."},
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	emailAddr := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	u, err := h.users.Register(r.Context(), username, emailAddr, password)
	if err != nil {
		msg := "Registration failed. Please try again."
		if errors.Is(err, ErrUsernameTaken) {
			msg = "That username is already taken."
		} else if errors.Is(err, ErrEmailTaken) {
			msg = "An account with that email already exists."
		} else if errors.Is(err, ErrPasswordTooShort) {
			msg = "Password must be at least 8 characters."
		} else if errors.Is(err, ErrUsernameRequired) {
			msg = "Username is required."
		} else if errors.Is(err, ErrEmailRequired) {
			msg = "Email is required."
		}
		h.render(w, r, "register.html", registerData{
			Flash:     &Flash{Type: "error", Message: msg},
			Username:  username,
			Email:     emailAddr,
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
		return
	}

	// When SMTP is configured the new account starts unverified and gets a
	// link. A send failure is logged, not fatal: the account is usable either
	// way and can request another link from the dashboard. Sent before the
	// session is created so a login hiccup cannot swallow the only email.
	if !u.EmailVerified {
		if err := h.sendVerificationEmail(r.Context(), r, u); err != nil {
			h.logger.Warn("register: send verification email", "user_id", u.ID, "error", err)
		}
	}

	// Auto-login after registration.
	h.record(r, authlog.Event{
		Event:    authlog.EventRegisterSuccess,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
	})
	token, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, nil, r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("create session after register", "error", err)
		http.Redirect(w, r, "/login?flash=registered", http.StatusFound)
		return
	}

	setSessionCookie(w, token, expiresAt, h.cfg)
	http.Redirect(w, r, "/", http.StatusFound)
}

// GetResetRequest renders the password reset request form.
func (h *Handler) GetResetRequest(w http.ResponseWriter, r *http.Request) {
	flashMsg := r.URL.Query().Get("flash")
	var flash *Flash
	if flashMsg != "" {
		flash = flashFromCode(flashMsg)
	}
	h.render(w, r, "reset_request.html", resetRequestData{
		Flash:     flash,
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// PostResetRequest handles the password reset request form submission.
// Always shows the same success message to avoid email enumeration.
func (h *Handler) PostResetRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "reset_request.html", resetRequestData{
			Flash:     &Flash{Type: "error", Message: "Invalid form submission."},
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
		return
	}

	// Record start time after the early-return parse check so that the minimum
	// response time applies only to the main success/failure path.
	start := time.Now()

	emailAddr := strings.TrimSpace(r.FormValue("email"))

	token, err := h.users.GeneratePasswordReset(r.Context(), emailAddr)
	if err != nil {
		h.logger.Error("generate password reset", "error", err)
		// Fall through and show the generic success message to avoid enumeration.
	}

	baseURL := h.cfg.Server.BaseURL
	if baseURL == "" {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		baseURL = scheme + "://" + r.Host
	}
	if token != "" {
		resetURL := baseURL + "/reset/" + token
		if err := h.mailer.SendPasswordReset(r.Context(), emailAddr, "", resetURL); err != nil {
			h.logger.Warn("send password reset email", "error", err, "email", emailAddr)
		}
	}

	// Enforce a minimum response time to mitigate email enumeration via timing.
	const minResponseTime = 200 * time.Millisecond
	if elapsed := time.Since(start); elapsed < minResponseTime {
		time.Sleep(minResponseTime - elapsed)
	}

	// Always show the same response regardless of whether the email was found.
	h.render(w, r, "reset_request.html", resetRequestData{
		Flash: &Flash{
			Type:    "success",
			Message: "If that email address has an account, a reset link has been sent.",
		},
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// GetResetConfirm renders the new password form for a given token.
func (h *Handler) GetResetConfirm(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	h.render(w, r, "reset_confirm.html", resetConfirmData{
		Token:     token,
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// PostResetConfirm handles new password submission.
func (h *Handler) PostResetConfirm(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	if err := r.ParseForm(); err != nil {
		h.render(w, r, "reset_confirm.html", resetConfirmData{
			Flash:     &Flash{Type: "error", Message: "Invalid form submission."},
			Token:     token,
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
		return
	}

	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")

	if password != confirm {
		h.render(w, r, "reset_confirm.html", resetConfirmData{
			Flash:     &Flash{Type: "error", Message: "Passwords do not match."},
			Token:     token,
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
		return
	}

	if err := h.users.ResetPassword(r.Context(), token, password); err != nil {
		msg := "Unable to reset password. Please try again."
		if errors.Is(err, ErrTokenExpired) {
			msg = "This reset link has expired. Please request a new one."
		} else if errors.Is(err, ErrTokenUsed) {
			msg = "This reset link has already been used."
		} else if errors.Is(err, ErrPasswordTooShort) {
			msg = "Password must be at least 8 characters."
		}
		h.render(w, r, "reset_confirm.html", resetConfirmData{
			Flash:     &Flash{Type: "error", Message: msg},
			Token:     token,
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
		return
	}

	http.Redirect(w, r, "/login?flash=password-reset", http.StatusFound)
}

// GetLogout revokes the current session, clears the cookie, and redirects to /login.
func (h *Handler) GetLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.Session.EffectiveCookieName())
	if err == nil {
		outcome := authlog.OutcomeSuccess
		detail := ""
		if err := h.sessions.RevokeSession(r.Context(), cookie.Value); err != nil {
			h.logger.Warn("revoke session on logout", "error", err)
			outcome = authlog.OutcomeFailure
			detail = "session revoke failed"
		}
		h.record(r, authlog.Event{
			Event:   authlog.EventLogout,
			Outcome: outcome,
			Detail:  detail,
		})
	}
	clearSessionCookie(w, h.cfg)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// render executes a named template into a buffer and writes the result to w.
// Buffering ensures the status code and headers are not sent if the template
// execution fails partway through.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.Error("render template", "name", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// lockedLoginMessage is the generic message shown while an account is locked.
// The wording is identical for known and unknown usernames.
func lockedLoginMessage(remaining time.Duration) string {
	minutes := int((remaining + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	return fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", minutes)
}

// renderLoginError is a convenience wrapper for re-rendering the login form with an error.
func (h *Handler) renderLoginError(w http.ResponseWriter, r *http.Request, msg, rd, username string) {
	h.render(w, r, "login.html", loginData{
		Flash:             &Flash{Type: "error", Message: msg},
		RedirectTo:        rd,
		Username:          username,
		AllowRegistration: h.registrationAllowed(r.Context()),
		AllowPassword:     isAuthMethodEnabled(r.Context(), h.settings, SettingPasswordEnabled),
		AllowPasskey:      isAuthMethodEnabled(r.Context(), h.settings, SettingPasskeyEnabled),
		AllowMagicLink:    isAuthMethodEnabled(r.Context(), h.settings, SettingMagicLinkEnabled),
		CSRFToken:         csrf.TokenFromContext(r.Context()),
	})
}

// setSessionCookie writes the session cookie with the given token and expiry.
func setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Session.EffectiveCookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie writes an expired cookie to clear the session.
func clearSessionCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Session.EffectiveCookieName(),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// flashFromCode converts a flash query param code into a Flash message.
func flashFromCode(code string) *Flash {
	switch code {
	case "password-reset":
		return &Flash{Type: "success", Message: "Your password has been reset. Please sign in."}
	case "registration-disabled":
		return &Flash{Type: "error", Message: "Registration is currently disabled."}
	case "registered":
		return &Flash{Type: "success", Message: "Account created. Please sign in."}
	case "link-expired":
		return &Flash{Type: "error", Message: "This sign-in link has expired. Please request a new one."}
	case "link-used":
		return &Flash{Type: "error", Message: "This sign-in link has already been used."}
	case "invalid-token":
		return &Flash{Type: "error", Message: "This sign-in link is invalid. Please request a new one."}
	case "account-inactive":
		return &Flash{Type: "error", Message: "Your account is inactive. Please contact an administrator."}
	case "email-verified":
		return &Flash{Type: "success", Message: "Your email address has been verified."}
	case "email-already-verified":
		return &Flash{Type: "info", Message: "Your email address is already verified."}
	case "verify-resent":
		return &Flash{Type: "success", Message: "Verification email sent. Check your inbox."}
	case "verify-send-failed":
		return &Flash{Type: "error", Message: "Could not send the verification email. Please try again later."}
	case "verify-link-invalid":
		return &Flash{Type: "error", Message: "This verification link is invalid or has expired."}
	case "verify-link-expired":
		return &Flash{Type: "error", Message: "This verification link has expired. Sign in to request a new one."}
	case "verify-link-used":
		return &Flash{Type: "error", Message: "This verification link has already been used."}
	default:
		return nil
	}
}

// ─── Initial Setup ────────────────────────────────────────────────────────────

// setupData is the template data for the /setup page.
type setupData struct {
	Flash     *Flash
	CSRFToken string
}

// GetSetup returns an HTTP handler that renders the initial setup form.
// If setupManager is nil or its token is no longer active (expired or already
// used), the handler redirects to /login — the setup endpoint is self-disabling.
func (h *Handler) GetSetup(setupManager *SetupTokenManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if setupManager == nil || !setupManager.IsActive() {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		h.render(w, r, "setup.html", setupData{
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
	}
}

// PostSetup returns an HTTP handler that processes the initial admin account
// creation form. It validates the one-time setup token, creates the admin user,
// and logs them in. The setup endpoint becomes unavailable after this succeeds.
func (h *Handler) PostSetup(setupManager *SetupTokenManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if setupManager == nil || !setupManager.IsActive() {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		if err := r.ParseForm(); err != nil {
			h.render(w, r, "setup.html", setupData{
				Flash:     &Flash{Type: "error", Message: "Invalid form submission."},
				CSRFToken: csrf.TokenFromContext(r.Context()),
			})
			return
		}

		token := strings.TrimSpace(r.FormValue("setup_token"))
		username := strings.TrimSpace(r.FormValue("username"))
		emailAddr := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		confirm := r.FormValue("password_confirm")

		// Validate password match before consuming the one-time token so a typo
		// does not burn the token.
		if password != confirm {
			h.render(w, r, "setup.html", setupData{
				Flash:     &Flash{Type: "error", Message: "Passwords do not match."},
				CSRFToken: csrf.TokenFromContext(r.Context()),
			})
			return
		}

		if !setupManager.Consume(token) {
			h.render(w, r, "setup.html", setupData{
				Flash:     &Flash{Type: "error", Message: "Invalid or expired setup token."},
				CSRFToken: csrf.TokenFromContext(r.Context()),
			})
			return
		}

		u, err := h.users.CreateAdmin(r.Context(), username, emailAddr, password)
		if err != nil {
			msg := "Failed to create admin account. Please try again."
			switch {
			case errors.Is(err, ErrUsernameTaken):
				msg = "That username is already taken."
			case errors.Is(err, ErrEmailTaken):
				msg = "An account with that email already exists."
			case errors.Is(err, ErrPasswordTooShort):
				msg = "Password must be at least 8 characters."
			case errors.Is(err, ErrUsernameRequired):
				msg = "Username is required."
			case errors.Is(err, ErrEmailRequired):
				msg = "Email is required."
			}
			h.render(w, r, "setup.html", setupData{
				Flash:     &Flash{Type: "error", Message: msg},
				CSRFToken: csrf.TokenFromContext(r.Context()),
			})
			return
		}

		// Auto-login the new admin.
		sessionToken, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, nil, r.RemoteAddr, r.UserAgent())
		if err != nil {
			h.logger.Error("setup: create session after admin creation", "error", err)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		setSessionCookie(w, sessionToken, expiresAt, h.cfg)
		http.Redirect(w, r, "/admin", http.StatusFound)
	}
}
