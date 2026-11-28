package user

import (
	"errors"
	"net/http"
	"strings"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/web"
)

// registerData is the template data for the register page.
type registerData struct {
	Flash     *Flash
	Username  string
	Email     string
	CSRFToken string
}

// registerDisabledData is the render data for the "registration is disabled"
// page.
type registerDisabledData struct {
	Tagline string
}

// GetRegister renders the registration form.
func (h *Handler) GetRegister(w http.ResponseWriter, r *http.Request) {
	if !h.registrationAllowed(r.Context()) {
		h.renderRegisterDisabled(w, r)
		return
	}
	h.render(w, r, "register.html", registerData{
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// renderRegisterDisabled answers a visit to /register while self-registration
// is off. A dedicated page reads as an intentional state; a redirect to /login
// with an error flash made a URL the visitor typed look like a failure they
// caused.
func (h *Handler) renderRegisterDisabled(w http.ResponseWriter, r *http.Request) {
	web.RenderStatus(w, h.tmpl, h.logger, http.StatusForbidden, "register-disabled", registerDisabledData{
		Tagline: h.tagline(r.Context()),
	})
}

// PostRegister handles registration form submission.
func (h *Handler) PostRegister(w http.ResponseWriter, r *http.Request) {
	if !h.registrationAllowed(r.Context()) {
		h.renderRegisterDisabled(w, r)
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
		if errors.Is(err, ErrRegistrationDisabled) {
			h.renderRegisterDisabled(w, r)
			return
		}
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
