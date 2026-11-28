package user

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
)

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

	if token != "" {
		resetURL := h.baseURL(r) + "/reset/" + token
		if err := h.mailer.SendPasswordReset(r.Context(), emailAddr, "", resetURL); err != nil {
			h.logger.Warn("send password reset email", "error", err, "email", emailAddr)
		}
	}

	// Enforce a minimum response time to mitigate email enumeration via timing.
	const minResponseTime = 200 * time.Millisecond
	if remaining := minResponseTime - time.Since(start); remaining > 0 {
		timer := time.NewTimer(remaining)
		select {
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
		}
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
		} else if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			msg = "Password must be at most 72 bytes."
		}
		h.render(w, r, "reset_confirm.html", resetConfirmData{
			Flash:     &Flash{Type: "error", Message: msg},
			Token:     token,
			CSRFToken: csrf.TokenFromContext(r.Context()),
		})
		return
	}

	h.record(r, authlog.Event{
		Event:   authlog.EventPasswordChanged,
		Outcome: authlog.OutcomeSuccess,
		Detail:  "password reset",
	})
	http.Redirect(w, r, "/login?flash=password-reset", http.StatusFound)
}
