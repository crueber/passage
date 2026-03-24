package user

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/email"
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

// Handler handles user-facing HTTP flows: login, register, password reset, logout.
type Handler struct {
	users    *Service
	sessions sessionCreator
	settings settingsReader
	mailer   email.Sender
	tmpl     *template.Template
	cfg      *config.Config
	logger   *slog.Logger
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(
	users *Service,
	sessions sessionCreator,
	settings settingsReader,
	mailer email.Sender,
	tmpl *template.Template,
	cfg *config.Config,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		users:    users,
		sessions: sessions,
		settings: settings,
		mailer:   mailer,
		tmpl:     tmpl,
		cfg:      cfg,
		logger:   logger,
	}
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

// loginData is the template data for the login page.
type loginData struct {
	Flash             *Flash
	RedirectTo        string
	Username          string
	AllowRegistration bool
}

// registerData is the template data for the register page.
type registerData struct {
	Flash    *Flash
	Username string
	Email    string
}

// resetRequestData is the template data for the reset request page.
type resetRequestData struct {
	Flash *Flash
}

// resetConfirmData is the template data for the reset confirmation page.
type resetConfirmData struct {
	Flash *Flash
	Token string
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
	})
}

// PostLogin handles credential submission.
func (h *Handler) PostLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderLoginError(w, r, "Invalid form submission.", r.FormValue("rd"), r.FormValue("username"))
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	rd := r.FormValue("rd")

	u, err := h.users.Authenticate(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserInactive) {
			h.renderLoginError(w, r, "Invalid username or password.", rd, username)
			return
		}
		h.logger.Error("authenticate user", "error", err)
		h.renderLoginError(w, r, "An error occurred. Please try again.", rd, username)
		return
	}

	token, expiresAt, err := h.sessions.CreateSession(r.Context(), u.ID, nil, r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("create session", "error", err)
		h.renderLoginError(w, r, "An error occurred. Please try again.", rd, username)
		return
	}

	setSessionCookie(w, token, expiresAt, h.cfg)

	// Check for passage_rd cookie first (set by /auth/start), then fall back
	// to the rd form field, then default to /.
	dest := "/"
	if rdCookie, err := r.Cookie("passage_rd"); err == nil && strings.HasPrefix(rdCookie.Value, "/") {
		dest = rdCookie.Value
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
	} else if rd != "" && strings.HasPrefix(rd, "/") {
		dest = rd
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// GetRegister renders the registration form.
func (h *Handler) GetRegister(w http.ResponseWriter, r *http.Request) {
	if !h.registrationAllowed(r.Context()) {
		http.Redirect(w, r, "/login?flash=registration-disabled", http.StatusFound)
		return
	}
	h.render(w, r, "register.html", registerData{})
}

// PostRegister handles registration form submission.
func (h *Handler) PostRegister(w http.ResponseWriter, r *http.Request) {
	if !h.registrationAllowed(r.Context()) {
		http.Redirect(w, r, "/login?flash=registration-disabled", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.render(w, r, "register.html", registerData{
			Flash: &Flash{Type: "error", Message: "Invalid form submission."},
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
			Flash:    &Flash{Type: "error", Message: msg},
			Username: username,
			Email:    emailAddr,
		})
		return
	}

	// Auto-login after registration.
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
	h.render(w, r, "reset_request.html", resetRequestData{Flash: flash})
}

// PostResetRequest handles the password reset request form submission.
// Always shows the same success message to avoid email enumeration.
func (h *Handler) PostResetRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "reset_request.html", resetRequestData{
			Flash: &Flash{Type: "error", Message: "Invalid form submission."},
		})
		return
	}

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

	// Always show the same response regardless of whether the email was found.
	h.render(w, r, "reset_request.html", resetRequestData{
		Flash: &Flash{
			Type:    "success",
			Message: "If that email address has an account, a reset link has been sent.",
		},
	})
}

// GetResetConfirm renders the new password form for a given token.
func (h *Handler) GetResetConfirm(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	h.render(w, r, "reset_confirm.html", resetConfirmData{Token: token})
}

// PostResetConfirm handles new password submission.
func (h *Handler) PostResetConfirm(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	if err := r.ParseForm(); err != nil {
		h.render(w, r, "reset_confirm.html", resetConfirmData{
			Flash: &Flash{Type: "error", Message: "Invalid form submission."},
			Token: token,
		})
		return
	}

	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")

	if password != confirm {
		h.render(w, r, "reset_confirm.html", resetConfirmData{
			Flash: &Flash{Type: "error", Message: "Passwords do not match."},
			Token: token,
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
			Flash: &Flash{Type: "error", Message: msg},
			Token: token,
		})
		return
	}

	http.Redirect(w, r, "/login?flash=password-reset", http.StatusFound)
}

// GetLogout revokes the current session, clears the cookie, and redirects to /login.
func (h *Handler) GetLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.Session.CookieName)
	if err == nil {
		if err := h.sessions.RevokeSession(r.Context(), cookie.Value); err != nil {
			h.logger.Warn("revoke session on logout", "error", err)
		}
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

// renderLoginError is a convenience wrapper for re-rendering the login form with an error.
func (h *Handler) renderLoginError(w http.ResponseWriter, r *http.Request, msg, rd, username string) {
	h.render(w, r, "login.html", loginData{
		Flash:             &Flash{Type: "error", Message: msg},
		RedirectTo:        rd,
		Username:          username,
		AllowRegistration: h.registrationAllowed(r.Context()),
	})
}

// setSessionCookie writes the session cookie with the given token and expiry.
func setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Session.CookieName,
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
		Name:     cfg.Session.CookieName,
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
	default:
		return nil
	}
}
