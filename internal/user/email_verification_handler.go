package user

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

// GetVerifyEmail consumes an email verification token from a link in an email.
//
// It is a public GET (email clients cannot send a CSRF token) and it never
// touches authentication: a valid token only flips the informational
// email_verified flag. Invalid, expired, or already-used tokens redirect with
// an error flash instead of failing the request.
func (h *Handler) GetVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		http.Redirect(w, r, "/login?flash=verify-link-invalid", http.StatusFound)
		return
	}

	u, err := h.users.ConsumeEmailVerificationToken(r.Context(), token)
	if err != nil {
		switch {
		case errors.Is(err, ErrEmailVerificationTokenExpired):
			http.Redirect(w, r, "/login?flash=verify-link-expired", http.StatusFound)
		case errors.Is(err, ErrEmailVerificationTokenUsed):
			http.Redirect(w, r, "/login?flash=verify-link-used", http.StatusFound)
		case errors.Is(err, ErrEmailVerificationTokenNotFound):
			http.Redirect(w, r, "/login?flash=verify-link-invalid", http.StatusFound)
		default:
			h.logger.Error("verify email: consume token", "error", err)
			http.Redirect(w, r, "/login?flash=error", http.StatusFound)
		}
		return
	}

	// Show the confirmation on the dashboard only when the signed-in account is
	// the one that was verified. run.go attaches the user for valid sessions.
	if sessionUser, ok := h.userCtx(r.Context()); ok && sessionUser != nil && u != nil && sessionUser.ID == u.ID {
		http.Redirect(w, r, "/?flash=email-verified", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login?flash=email-verified", http.StatusFound)
}

// PostVerifyEmailResend issues a fresh verification token for the signed-in
// user and emails a new link. Earlier unused tokens are invalidated by the
// token store, so only the newest link works.
func (h *Handler) PostVerifyEmailResend(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if u.EmailVerified {
		http.Redirect(w, r, "/?flash=email-already-verified", http.StatusFound)
		return
	}

	if err := h.sendVerificationEmail(r.Context(), r, u); err != nil {
		h.logger.Warn("verify email: resend", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/?flash=verify-send-failed", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/?flash=verify-resent", http.StatusFound)
}

// sendVerificationEmail creates a token and sends the verification link. The
// caller decides what a failure means; it must never fail the surrounding
// flow, because a broken mail server must not break registration or sign-in.
func (h *Handler) sendVerificationEmail(ctx context.Context, r *http.Request, u *User) error {
	tok, err := h.users.CreateEmailVerificationToken(ctx, u.ID, u.Email)
	if err != nil {
		return fmt.Errorf("create verification token: %w", err)
	}

	verifyURL := h.baseURL(r) + "/verify-email/" + url.PathEscape(tok.Token)
	if err := h.mailer.SendVerifyEmail(ctx, u.Email, u.Name, verifyURL); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}
	return nil
}

// baseURL returns the absolute origin used to build links in emails. It
// prefers server.base_url and falls back to the request when it is unset
// (development only; production configurations set base_url).
func (h *Handler) baseURL(r *http.Request) string {
	if h.cfg.Server.BaseURL != "" {
		return strings.TrimRight(h.cfg.Server.BaseURL, "/")
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}
