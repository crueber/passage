package user

import (
	"errors"
	"net/http"
	"strings"

	"github.com/crueber/passage/internal/csrf"
)

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

		// Validate all form inputs before consuming the one-time setup token so
		// a typo or missing field never burns the token and locks out setup.
		var validationErr string
		switch {
		case username == "":
			validationErr = "Username is required."
		case emailAddr == "":
			validationErr = "Email is required."
		case len(password) < 8:
			validationErr = "Password must be at least 8 characters."
		case password != confirm:
			validationErr = "Passwords do not match."
		}
		if validationErr != "" {
			h.render(w, r, "setup.html", setupData{
				Flash:     &Flash{Type: "error", Message: validationErr},
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
