package user

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/crueber/passage/internal/csrf"
)

type magicLinkRequestData struct {
	Flash      *Flash
	Email      string
	RedirectTo string
	CSRFToken  string
}

type magicLinkSentData struct{}

// GetMagicLinkRequest renders the email input form for magic link login.
func (h *Handler) GetMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	if !isAuthMethodEnabled(r.Context(), h.settings, SettingMagicLinkEnabled) {
		http.Error(w, "Method not allowed", http.StatusForbidden)
		return
	}
	rd := r.URL.Query().Get("rd")
	flash := flashFromCode(r.URL.Query().Get("flash"))
	h.render(w, r, "magic_link_request.html", magicLinkRequestData{
		Flash:      flash,
		RedirectTo: rd,
		CSRFToken:  csrf.TokenFromContext(r.Context()),
	})
}

// PostMagicLinkRequest creates or finds a user by email, then sends them a magic link.
func (h *Handler) PostMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	if !isAuthMethodEnabled(r.Context(), h.settings, SettingMagicLinkEnabled) {
		http.Error(w, "Method not allowed", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login/magic", http.StatusFound)
		return
	}
	ctx := r.Context()
	email := strings.TrimSpace(r.FormValue("email"))
	rd := r.FormValue("rd")
	// Open-redirect guard: only accept relative paths starting with "/" but not "//".
	if rd != "" && !(strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//")) {
		rd = ""
	}

	renderErr := func(msg string) {
		h.render(w, r, "magic_link_request.html", magicLinkRequestData{
			Flash:      &Flash{Type: "error", Message: msg},
			Email:      email,
			RedirectTo: rd,
			CSRFToken:  csrf.TokenFromContext(ctx),
		})
	}

	if email == "" || !strings.Contains(email, "@") {
		renderErr("Please enter a valid email address.")
		return
	}

	if h.cfg.SMTP.Host == "" {
		renderErr("Magic links require SMTP to be configured.")
		return
	}

	// Read TTL from settings; default to 15.
	ttlMinutes := 15
	if ttlStr, err := h.settings.Get(ctx, "magic_link_ttl_minutes"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(ttlStr)); err == nil && n > 0 {
			ttlMinutes = n
		}
	}

	u, _, err := h.users.FindOrCreateByEmail(ctx, email)
	if err != nil {
		h.logger.Error("magic link: find or create user", "email", email, "error", err)
		renderErr("Something went wrong. Please try again.")
		return
	}

	tok, err := h.users.CreateMagicLinkToken(ctx, u.ID, ttlMinutes)
	if err != nil {
		h.logger.Error("magic link: create token", "user_id", u.ID, "error", err)
		renderErr("Something went wrong. Please try again.")
		return
	}

	magicURL := h.cfg.Server.BaseURL + "/login/magic/verify?token=" + url.QueryEscape(tok.Token)
	if rd != "" {
		magicURL += "&rd=" + url.QueryEscape(rd)
	}

	// u.Email is always non-empty at this point (it was used to find/create the user).
	displayName := u.Email
	if err := h.mailer.SendMagicLink(ctx, email, displayName, magicURL); err != nil {
		h.logger.Warn("magic link: send email", "email", email, "error", err)
		renderErr("Failed to send email. Please try again.")
		return
	}

	h.render(w, r, "magic_link_sent.html", magicLinkSentData{})
}

// GetMagicLinkVerify consumes a magic link token and creates a session.
func (h *Handler) GetMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	if !isAuthMethodEnabled(r.Context(), h.settings, SettingMagicLinkEnabled) {
		http.Error(w, "Method not allowed", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/login/magic?flash=invalid-token", http.StatusFound)
		return
	}

	u, err := h.users.ConsumeMagicLinkToken(ctx, token)
	if err != nil {
		switch {
		case errors.Is(err, ErrMagicLinkTokenExpired):
			http.Redirect(w, r, "/login/magic?flash=link-expired", http.StatusFound)
		case errors.Is(err, ErrMagicLinkTokenUsed):
			http.Redirect(w, r, "/login/magic?flash=link-used", http.StatusFound)
		case errors.Is(err, ErrMagicLinkTokenNotFound):
			http.Redirect(w, r, "/login/magic?flash=invalid-token", http.StatusFound)
		default:
			h.logger.Error("magic link: consume token", "error", err)
			http.Redirect(w, r, "/login?flash=error", http.StatusFound)
		}
		return
	}

	if !u.IsActive {
		http.Redirect(w, r, "/login?flash=account-inactive", http.StatusFound)
		return
	}

	ip := r.RemoteAddr
	ua := r.Header.Get("User-Agent")
	sessionToken, expiresAt, err := h.sessions.CreateSession(ctx, u.ID, nil, ip, ua)
	if err != nil {
		h.logger.Error("magic link: create session", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/login?flash=error", http.StatusFound)
		return
	}

	setSessionCookie(w, sessionToken, expiresAt, h.cfg)

	// Redirect: passage_rd cookie → rd query param → /admin for admins → /.
	// Open-redirect guard: only redirect to paths that start with "/" but not "//".
	rd := r.URL.Query().Get("rd")
	if rdCookie, err := r.Cookie("passage_rd"); err == nil && rdCookie.Value != "" && rd == "" {
		rd = rdCookie.Value
		// Clear the cookie.
		http.SetCookie(w, &http.Cookie{Name: "passage_rd", Value: "", MaxAge: -1, Path: "/"})
	}
	if rd != "" && strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//") {
		http.Redirect(w, r, rd, http.StatusFound)
		return
	}
	if u.IsAdmin {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
