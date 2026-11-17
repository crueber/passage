package user

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/settings"
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

// PostMagicLinkRequest sends a sign-in link to an account that already exists.
//
// The response never varies: every outcome — an existing account, one that does
// not exist, a blocked address, a send failure — renders the same "if there is
// an account at that address, it has been sent" page. The request is never a
// way to learn whether an address is registered.
//
// No account is ever created here. A request for an address with no user is a
// failed guess; the threshold and window are the admin Magic link rate limit,
// and reaching it blocks that client address for 24 hours (see
// ratelimit.MagicLinkService), so the endpoint is also not a cheap account
// oracle.
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
	// Open-redirect guard: only accept relative paths starting with "/" but not
	// "//" and containing no "\" (browsers normalize "\" to "/", so "/\evil.com"
	// is equivalent to "//evil.com").
	if !safeReturnPath(rd) {
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

	// Only malformed input gets an error page; it says nothing about accounts.
	if email == "" || !strings.Contains(email, "@") {
		renderErr("Please enter a valid email address.")
		return
	}
	if settings.String(ctx, h.settings, settings.SMTPHost, h.cfg.SMTP.Host) == "" {
		renderErr("Magic links require SMTP to be configured.")
		return
	}

	renderSent := func() {
		h.render(w, r, "magic_link_sent.html", magicLinkSentData{})
	}

	// A blocked address is answered exactly like everyone else; the block must
	// not double as an account-existence signal.
	if h.magicThrottle != nil {
		status, err := h.magicThrottle.Status(ctx, authlog.ClientIP(r))
		if err != nil {
			h.logger.Warn("magic link: throttle status", "error", err)
		} else if status.Locked {
			h.record(r, authlog.Event{
				Event:    authlog.EventMagicLinkThrottled,
				Outcome:  authlog.OutcomeThrottled,
				Username: email,
				Detail:   "address locked",
			})
			renderSent()
			return
		}
	}

	// Read TTL from settings; default to 15.
	ttlMinutes := 15
	if ttlStr, err := h.settings.Get(ctx, "magic_link_ttl_minutes"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(ttlStr)); err == nil && n > 0 {
			ttlMinutes = n
		}
	}

	u, err := h.users.GetByEmail(ctx, email)
	switch {
	case errors.Is(err, ErrNotFound):
		h.recordMagicLinkMiss(r, email)
		renderSent()
		return
	case err != nil:
		// A lookup failure is a server problem, not an answer about the
		// address; the caller learns nothing either way.
		h.logger.Error("magic link: find user", "error", err)
		renderSent()
		return
	}

	if !u.IsActive {
		h.record(r, authlog.Event{
			Event:    authlog.EventMagicLinkFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "account inactive",
		})
		renderSent()
		return
	}

	tok, err := h.users.CreateMagicLinkToken(ctx, u.ID, ttlMinutes)
	if err != nil {
		h.logger.Error("magic link: create token", "user_id", u.ID, "error", err)
		renderSent()
		return
	}

	magicURL := h.cfg.Server.BaseURL + "/login/magic/verify?token=" + url.QueryEscape(tok.Token)
	if rd != "" {
		magicURL += "&rd=" + url.QueryEscape(rd)
	}

	// u.Email is always non-empty at this point (it was used to find the user).
	displayName := u.Email
	if err := h.mailer.SendMagicLink(ctx, email, displayName, magicURL); err != nil {
		h.logger.Warn("magic link: send email", "email", email, "error", err)
	}

	renderSent()
}

// recordMagicLinkMiss counts a request for an address that has no account and
// records it for the security log. The caller renders the shared "sent" page;
// nothing here influences the response, so a guess cannot be observed.
func (h *Handler) recordMagicLinkMiss(r *http.Request, email string) {
	ctx := r.Context()
	locked := false
	if h.magicThrottle != nil {
		status, err := h.magicThrottle.RecordFailure(ctx, authlog.ClientIP(r))
		if err != nil {
			// Fail open: a throttle-store problem must not turn every request
			// into an error, but it is worth a log line.
			h.logger.Warn("magic link: record failure", "error", err)
		}
		locked = status.Locked
	}

	if locked {
		h.record(r, authlog.Event{
			Event:    authlog.EventMagicLinkThrottled,
			Outcome:  authlog.OutcomeThrottled,
			Username: email,
			Detail:   "address locked after failed attempts",
		})
		return
	}

	h.record(r, authlog.Event{
		Event:    authlog.EventMagicLinkFailure,
		Outcome:  authlog.OutcomeFailure,
		Username: email,
		Detail:   "unknown account",
	})
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
		detail := "invalid token"
		switch {
		case errors.Is(err, ErrMagicLinkTokenExpired):
			detail = "expired token"
		case errors.Is(err, ErrMagicLinkTokenUsed):
			detail = "token already used"
		case errors.Is(err, ErrMagicLinkTokenNotFound):
			detail = "unknown token"
		default:
			detail = "internal error"
		}
		h.record(r, authlog.Event{
			Event:   authlog.EventMagicLinkFailure,
			Outcome: authlog.OutcomeFailure,
			Detail:  detail,
		})
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
		h.record(r, authlog.Event{
			Event:    authlog.EventMagicLinkFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "account inactive",
		})
		http.Redirect(w, r, "/login?flash=account-inactive", http.StatusFound)
		return
	}

	// Using the link proves control of the mailbox, so an unverified account
	// becomes verified. Failures are logged only — verification never gates
	// sign-in.
	if !u.EmailVerified {
		if err := h.users.MarkEmailVerified(ctx, u.ID); err != nil {
			h.logger.Warn("magic link: mark email verified", "user_id", u.ID, "error", err)
		}
	}

	ip := r.RemoteAddr
	ua := r.Header.Get("User-Agent")

	// Resolve the return target before creating the session: an OAuth
	// authorization request names the app, and that app may override the
	// session duration (see Handler.appIDFromReturnTarget).
	rd := r.URL.Query().Get("rd")
	clearReturnCookie := false
	if rdCookie, err := r.Cookie("passage_rd"); err == nil && rdCookie.Value != "" && rd == "" {
		rd = rdCookie.Value
		clearReturnCookie = true
	}
	if !safeReturnPath(rd) {
		rd = ""
	}

	// No second factor is requested here, deliberately: consuming the link
	// proves control of the mailbox, which is the same "something you have"
	// property a TOTP code provides. MFA enforcement lives in Handler.PostLogin,
	// on the password flow only.
	sessionToken, expiresAt, err := h.sessions.CreateSession(ctx, u.ID, h.appIDFromReturnTarget(ctx, rd), ip, ua)
	if err != nil {
		h.logger.Error("magic link: create session", "user_id", u.ID, "error", err)
		h.record(r, authlog.Event{
			Event:    authlog.EventMagicLinkFailure,
			Outcome:  authlog.OutcomeFailure,
			UserID:   u.ID,
			Username: u.Username,
			Detail:   "session create failed",
		})
		http.Redirect(w, r, "/login?flash=error", http.StatusFound)
		return
	}

	setSessionCookie(w, sessionToken, expiresAt, h.cfg)
	h.record(r, authlog.Event{
		Event:    authlog.EventMagicLinkLogin,
		Outcome:  authlog.OutcomeSuccess,
		UserID:   u.ID,
		Username: u.Username,
		Detail:   "magic link",
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

	// Redirect: rd → /admin for admins → /.
	if rd != "" {
		http.Redirect(w, r, rd, http.StatusFound)
		return
	}
	if u.IsAdmin {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
