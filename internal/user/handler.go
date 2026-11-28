package user

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/email"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/web"
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
	// FavoriteIDs returns the apps this user pinned to the top of the dashboard.
	FavoriteIDs(ctx context.Context, userID string) (map[string]bool, error)
	// ToggleFavorite flips a pin. found is false when the user has no access.
	ToggleFavorite(ctx context.Context, userID, appID string) (favorite, found bool, err error)
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

// magicLinkThrottle is the per-address throttle for magic-link requests.
// Defined at the consumer boundary; backed by *ratelimit.MagicLinkService in
// run.go. It only counts requests for addresses that have no account.
type magicLinkThrottle interface {
	Status(ctx context.Context, ip string) (ratelimit.MagicLinkStatus, error)
	RecordFailure(ctx context.Context, ip string) (ratelimit.MagicLinkStatus, error)
}

// ProviderButton is one upstream sign-in button on the log-in page.
type ProviderButton struct {
	Name  string
	Label string
}

// ProviderSource lists the upstream providers for the log-in page. Defined at
// the consumer boundary (the user package cannot import idp: idp imports user)
// and backed by the idp provider store in run.go.
type ProviderSource interface {
	ProviderButtons(ctx context.Context) ([]ProviderButton, error)
}

// Handler handles user-facing HTTP flows: login, register, password reset, logout.
type Handler struct {
	users    *Service
	mfa      *mfa.Service
	apps     AppLister
	sessions sessionCreator
	settings settingsReader
	mailer   email.Sender
	userCtx  userContextReader
	// authEvents records authentication events. May be nil (tests).
	authEvents authEventRecorder
	// throttle is the per-account password-login throttle. May be nil.
	throttle loginThrottle
	// magicThrottle blocks addresses that keep asking for sign-in links to
	// addresses with no account. May be nil (tests).
	magicThrottle magicLinkThrottle
	// passkey is the WebAuthn bridge that can complete a pending second-factor
	// challenge. May be nil (passkeys disabled, or tests).
	passkey secondFactorPasskey
	// providers lists upstream identity providers for the log-in page.
	providers ProviderSource
	tmpl      *template.Template
	cfg       *config.Config
	logger    *slog.Logger
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(
	users *Service,
	mfaSvc *mfa.Service,
	apps AppLister,
	sessions sessionCreator,
	settings settingsReader,
	mailer email.Sender,
	userCtx userContextReader,
	authEvents authEventRecorder,
	throttle loginThrottle,
	magicThrottle magicLinkThrottle,
	tmpl *template.Template,
	cfg *config.Config,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		users:         users,
		mfa:           mfaSvc,
		apps:          apps,
		sessions:      sessions,
		settings:      settings,
		mailer:        mailer,
		userCtx:       userCtx,
		authEvents:    authEvents,
		throttle:      throttle,
		magicThrottle: magicThrottle,
		tmpl:          tmpl,
		cfg:           cfg,
		logger:        logger,
	}
}

// SetProviderSource wires the upstream provider list. Call once before serving;
// a nil source renders no provider buttons.
func (h *Handler) SetProviderSource(src ProviderSource) {
	h.providers = src
}

const (
	// SettingTagline is the settings-store key behind the line of text under
	// the sign-in card. It is presentation text, so it is edited in the admin
	// UI rather than the config file.
	SettingTagline = "login_tagline"

	// DefaultTagline is shown when the setting has never been written. An
	// explicitly empty value hides the line instead.
	DefaultTagline = "Self-hosted authentication for your home lab"

	// MaxTaglineLength bounds the setting: it is a caption, not a paragraph.
	MaxTaglineLength = 120

	// SettingHeaderPhrase is the custom word or phrase shown in the sign-in
	// header, and SettingHeaderStyle says how it is combined with the name.
	SettingHeaderPhrase = "login_header_phrase"
	SettingHeaderStyle  = "login_header_style"

	// HeaderStyleFor renders "passage for <phrase>"; HeaderStylePlain renders
	// the phrase on its own.
	HeaderStyleFor   = "for"
	HeaderStylePlain = "plain"

	// DefaultWordmark is the header when no phrase is configured.
	DefaultWordmark = "passage"

	// MaxHeaderPhraseLength keeps the header a wordmark rather than a sentence.
	MaxHeaderPhraseLength = 60
)

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

// registrationAllowed reports the stored registration policy. The admin UI is
// the only place it is set; the config snapshot is just the default when the
// row is missing.
func (h *Handler) registrationAllowed(ctx context.Context) bool {
	return settings.Bool(ctx, h.settings, settings.AllowRegistration, h.cfg.Auth.AllowRegistration)
}

// safeReturnPath reports whether rd is a same-site absolute path that is safe
// to redirect to.
func safeReturnPath(rd string) bool {
	return web.SafeReturnPath(rd)
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

// resolveReturnDestination returns where a successful password login should
// send the user, and whether the passage_rd cookie supplied it (so the caller
// can clear the consumed cookie).
//
// Precedence is unchanged from the original inline logic: a safe passage_rd
// cookie wins over the submitted rd field (forward-auth bounces set the cookie
// before the form ever renders), then the rd field, then /admin for admins.
func (h *Handler) resolveReturnDestination(r *http.Request, u *User, rd string) (dest string, clearRDCookie bool) {
	if rdVal, ok := web.ReadReturnCookie(r); ok && safeReturnPath(rdVal) {
		return rdVal, true
	}
	if safeReturnPath(rd) {
		return rd, false
	}
	if u.IsAdmin {
		// No explicit redirect destination: send admins directly to the admin
		// dashboard rather than the homepage.
		return "/admin", false
	}
	return "/", false
}

// settingString reads one settings-store value, trimmed, with a fallback for a
// missing key or store error.
func (h *Handler) settingString(ctx context.Context, key, fallback string) string {
	if h.settings == nil {
		return fallback
	}
	if v, err := h.settings.Get(ctx, key); err == nil {
		return strings.TrimSpace(v)
	}
	return fallback
}

// tagline returns the configured text under the sign-in card. A stored empty
// value hides it; a missing setting falls back to the default.
func (h *Handler) tagline(ctx context.Context) string {
	return h.settingString(ctx, SettingTagline, DefaultTagline)
}

// wordmark returns the text next to the logo in the sign-in header: "passage",
// "passage for <phrase>", or the phrase alone when the operator chose the plain
// style.
func (h *Handler) wordmark(ctx context.Context) string {
	phrase := h.settingString(ctx, SettingHeaderPhrase, "")
	if phrase == "" {
		return DefaultWordmark
	}
	if h.settingString(ctx, SettingHeaderStyle, HeaderStyleFor) == HeaderStylePlain {
		return phrase
	}
	return DefaultWordmark + " for " + phrase
}

// providerButtons returns the upstream sign-in buttons, read live so a provider
// added in the admin UI appears without a restart.
func (h *Handler) providerButtons(ctx context.Context) []ProviderButton {
	if h.providers == nil {
		return nil
	}
	buttons, err := h.providers.ProviderButtons(ctx)
	if err != nil {
		h.logger.Error("login: list identity providers", "error", err)
		return nil
	}
	return buttons
}

// render executes a named template into a buffer and writes the result to w.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	web.Render(w, h.tmpl, h.logger, name, data)
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

// lockedLoginMessage is the generic message shown while an account is locked.
// The wording is identical for known and unknown usernames.
func lockedLoginMessage(remaining time.Duration) string {
	minutes := int((remaining + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	return fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", minutes)
}

// setSessionCookie writes the session cookie with the given token and expiry.
func setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, cfg *config.Config) {
	web.SetSessionCookie(w, cfg.Session, token, expiresAt)
}

// clearSessionCookie writes an expired cookie to clear the session.
func clearSessionCookie(w http.ResponseWriter, cfg *config.Config) {
	web.ClearSessionCookie(w, cfg.Session)
}

// clearReturnCookieIfPresent expires the passage_rd cookie consumed by a
// completed sign-in. Harmless when the cookie was never set.
func clearReturnCookieIfPresent(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	web.ClearReturnCookie(w, r, cfg.Session.CookieSecure)
}

// flashFromCode converts a flash query param code into a Flash message.
func flashFromCode(code string) *Flash {
	switch code {
	case "mfa-expired":
		return &Flash{Type: "error", Message: "Your sign-in attempt expired. Please sign in again."}
	case "password-reset":
		return &Flash{Type: "success", Message: "Your password has been reset. Please sign in."}
	case "password-changed":
		return &Flash{Type: "success", Message: "Your password has been changed. Please sign in again."}
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
	case "invite-invalid":
		return &Flash{Type: "error", Message: "This invitation link is invalid. Ask an administrator for a new invitation."}
	case "invite-expired":
		return &Flash{Type: "error", Message: "This invitation has expired. Ask an administrator for a new invitation."}
	case "invite-used":
		return &Flash{Type: "error", Message: "This invitation has already been used. Sign in instead, or ask an administrator for a new invitation."}
	case "idp-failed":
		return &Flash{Type: "error", Message: "Sign-in with the external provider failed. Please try again."}
	case "idp-no-account":
		return &Flash{Type: "error", Message: "No account is linked to that identity. Contact an administrator."}
	default:
		return nil
	}
}
