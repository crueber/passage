// Package settings defines the keys, defaults and accessors for values that
// are edited in the admin UI and stored in the SQLite settings table.
//
// The configuration file is bootstrap-only: where to listen, the public base
// URL, the database path, key material and logging. Every feature behaviour
// lives here instead, so the admin UI is the control surface. Values that a
// constructor needs are applied to the config snapshot once at startup by
// ApplyToConfig and act as the fallback for values components read live at use
// time. No setting requires a restart.
package settings

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/theme"
)

// Keys. The strings are the stored identifiers; renaming one orphans the row.
const (
	AllowRegistration = "allow_registration"

	SessionDurationHours      = "session_duration_hours"
	SessionIdleTimeoutMinutes = "session_idle_timeout_minutes"

	PasswordEnabled     = "auth_password_enabled"
	PasskeyEnabled      = "auth_passkey_enabled"
	MagicLinkEnabled    = "auth_magic_link_enabled"
	MagicLinkTTLMinutes = "magic_link_ttl_minutes"
	RequireMFA          = "auth_require_mfa"
	MaxLoginFailures    = "auth_max_login_failures"
	LockoutMinutes      = "auth_lockout_minutes"
	BcryptCost          = "auth_bcrypt_cost"

	Tagline      = "login_tagline"
	HeaderPhrase = "login_header_phrase"
	HeaderStyle  = "login_header_style"

	Theme = "ui_theme"

	SMTPHost     = "smtp_host"
	SMTPPort     = "smtp_port"
	SMTPUsername = "smtp_username"
	SMTPPassword = "smtp_password"
	SMTPTLS      = "smtp_tls"
	SMTPFrom     = "smtp_from"

	WebhookURL            = "webhook_url"
	WebhookSecret         = "webhook_secret"
	WebhookTimeoutSeconds = "webhook_timeout_seconds"

	MetricsEnabled = "metrics_enabled"
	MetricsToken   = "metrics_token"

	RateLimitLoginRequests          = "rate_limit_login_requests"
	RateLimitLoginWindowMinutes     = "rate_limit_login_window_minutes"
	RateLimitRegisterRequests       = "rate_limit_register_requests"
	RateLimitRegisterWindowMinutes  = "rate_limit_register_window_minutes"
	RateLimitResetRequests          = "rate_limit_reset_requests"
	RateLimitResetWindowMinutes     = "rate_limit_reset_window_minutes"
	RateLimitMagicLinkRequests      = "rate_limit_magic_link_requests"
	RateLimitMagicLinkWindowMinutes = "rate_limit_magic_link_window_minutes"
	RateLimitOAuthTokenRequests     = "rate_limit_oauth_token_requests"
	RateLimitOAuthTokenWindowMins   = "rate_limit_oauth_token_window_minutes"
	RateLimitSetupRequests          = "rate_limit_setup_requests"
	RateLimitSetupWindowMinutes     = "rate_limit_setup_window_minutes"
)

// DefaultTagline is the line under the sign-in card until an operator changes
// it. The user package re-exports it for its own render data.
const DefaultTagline = "Self-hosted authentication for your home lab"

// Defaults are the values every stored setting has until an operator changes
// it. They mirror the built-in config defaults so an untouched install behaves
// exactly as before this package existed.
var Defaults = map[string]string{
	AllowRegistration: "true",

	SessionDurationHours:      "24",
	SessionIdleTimeoutMinutes: "0",

	PasswordEnabled:     "true",
	PasskeyEnabled:      "true",
	MagicLinkEnabled:    "false",
	MagicLinkTTLMinutes: "15",
	RequireMFA:          "false",
	MaxLoginFailures:    "5",
	LockoutMinutes:      "15",
	BcryptCost:          "12",

	Tagline:      DefaultTagline,
	HeaderPhrase: "",
	HeaderStyle:  "for",

	Theme: theme.Default(),

	SMTPHost:     "",
	SMTPPort:     "587",
	SMTPUsername: "",
	SMTPPassword: "",
	SMTPTLS:      "starttls",
	SMTPFrom:     "",

	WebhookURL:            "",
	WebhookSecret:         "",
	WebhookTimeoutSeconds: "5",

	MetricsEnabled: "true",
	MetricsToken:   "",

	RateLimitLoginRequests:          "10",
	RateLimitLoginWindowMinutes:     "15",
	RateLimitRegisterRequests:       "10",
	RateLimitRegisterWindowMinutes:  "60",
	RateLimitResetRequests:          "5",
	RateLimitResetWindowMinutes:     "60",
	RateLimitMagicLinkRequests:      "5",
	RateLimitMagicLinkWindowMinutes: "60",
	RateLimitOAuthTokenRequests:     "20",
	RateLimitOAuthTokenWindowMins:   "1",
	RateLimitSetupRequests:          "5",
	RateLimitSetupWindowMinutes:     "60",
}

// Store is the minimal settings-store surface read by this package.
// Implemented by admin.SQLiteSettingsStore and by the per-package reader
// interfaces (they all expose the same Get).
type Store interface {
	Get(ctx context.Context, key string) (string, error)
}

// String returns the stored value, or fallback when it is missing or blank.
func String(ctx context.Context, s Store, key, fallback string) string {
	if s == nil {
		return fallback
	}
	v, err := s.Get(ctx, key)
	if err != nil {
		return fallback
	}
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// Raw returns the stored value exactly as written: missing and empty are
// distinct, which is what a field like the sign-in tagline needs (empty means
// "hide it", missing means "use the default").
func Raw(ctx context.Context, s Store, key, fallback string) string {
	if s == nil {
		return fallback
	}
	v, err := s.Get(ctx, key)
	if err != nil {
		return fallback
	}
	return v
}

// Bool returns the stored boolean, or fallback when missing or malformed.
func Bool(ctx context.Context, s Store, key string, fallback bool) bool {
	v, ok := lookup(ctx, s, key)
	if !ok {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "on", "1":
		return true
	case "false", "off", "0":
		return false
	default:
		return fallback
	}
}

// Int returns the stored integer, or fallback when missing, malformed or out
// of the inclusive range.
func Int(ctx context.Context, s Store, key string, fallback, min, max int) int {
	v, ok := lookup(ctx, s, key)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min || n > max {
		return fallback
	}
	return n
}

func lookup(ctx context.Context, s Store, key string) (string, bool) {
	if s == nil {
		return "", false
	}
	v, err := s.Get(ctx, key)
	if err != nil {
		return "", false
	}
	return v, true
}

// ApplyToConfig copies the stored settings into the config snapshot that
// constructors read. It runs once at startup and supplies the fallback for
// values components read live at use time; a value changed in the UI applies
// without another start.
//
// A malformed value is logged and the built-in default is kept: a broken row
// must not stop the server from starting.
func ApplyToConfig(ctx context.Context, s Store, cfg *config.Config, logger *slog.Logger) {
	if s == nil {
		return
	}
	cfg.Auth.AllowRegistration = Bool(ctx, s, AllowRegistration, cfg.Auth.AllowRegistration)
	cfg.Auth.BcryptCost = Int(ctx, s, BcryptCost, cfg.Auth.BcryptCost, 10, 31)
	cfg.Auth.MaxLoginFailures = Int(ctx, s, MaxLoginFailures, cfg.Auth.MaxLoginFailures, 0, 1000)
	cfg.Auth.LockoutMinutes = Int(ctx, s, LockoutMinutes, cfg.Auth.LockoutMinutes, 0, 100000)
	cfg.Auth.RequireMFA = Bool(ctx, s, RequireMFA, cfg.Auth.RequireMFA)

	cfg.Session.DurationHours = Int(ctx, s, SessionDurationHours, cfg.Session.DurationHours, 1, 8760)
	cfg.Session.IdleTimeoutMinutes = Int(ctx, s, SessionIdleTimeoutMinutes, cfg.Session.IdleTimeoutMinutes, 0, 8760)

	cfg.SMTP.Host = String(ctx, s, SMTPHost, cfg.SMTP.Host)
	cfg.SMTP.Port = Int(ctx, s, SMTPPort, cfg.SMTP.Port, 1, 65535)
	cfg.SMTP.Username = String(ctx, s, SMTPUsername, cfg.SMTP.Username)
	cfg.SMTP.Password = String(ctx, s, SMTPPassword, cfg.SMTP.Password)
	cfg.SMTP.TLS = String(ctx, s, SMTPTLS, cfg.SMTP.TLS)
	cfg.SMTP.From = String(ctx, s, SMTPFrom, cfg.SMTP.From)

	cfg.Security.WebhookURL = String(ctx, s, WebhookURL, cfg.Security.WebhookURL)
	cfg.Security.WebhookSecret = String(ctx, s, WebhookSecret, cfg.Security.WebhookSecret)
	cfg.Security.WebhookTimeoutSeconds = Int(ctx, s, WebhookTimeoutSeconds, cfg.Security.WebhookTimeoutSeconds, 1, 60)

	cfg.Metrics.Enabled = Bool(ctx, s, MetricsEnabled, cfg.Metrics.Enabled)
	cfg.Metrics.Token = Raw(ctx, s, MetricsToken, cfg.Metrics.Token)

	cfg.UI.Theme = String(ctx, s, Theme, cfg.UI.Theme)

	cfg.RateLimit.LoginRequests = Int(ctx, s, RateLimitLoginRequests, cfg.RateLimit.LoginRequests, 0, 100000)
	cfg.RateLimit.LoginWindowMinutes = Int(ctx, s, RateLimitLoginWindowMinutes, cfg.RateLimit.LoginWindowMinutes, 1, 100000)
	cfg.RateLimit.RegisterRequests = Int(ctx, s, RateLimitRegisterRequests, cfg.RateLimit.RegisterRequests, 0, 100000)
	cfg.RateLimit.RegisterWindowMinutes = Int(ctx, s, RateLimitRegisterWindowMinutes, cfg.RateLimit.RegisterWindowMinutes, 1, 100000)
	cfg.RateLimit.ResetRequests = Int(ctx, s, RateLimitResetRequests, cfg.RateLimit.ResetRequests, 0, 100000)
	cfg.RateLimit.ResetWindowMinutes = Int(ctx, s, RateLimitResetWindowMinutes, cfg.RateLimit.ResetWindowMinutes, 1, 100000)
	cfg.RateLimit.MagicLinkRequests = Int(ctx, s, RateLimitMagicLinkRequests, cfg.RateLimit.MagicLinkRequests, 0, 100000)
	cfg.RateLimit.MagicLinkWindowMinutes = Int(ctx, s, RateLimitMagicLinkWindowMinutes, cfg.RateLimit.MagicLinkWindowMinutes, 1, 100000)
	cfg.RateLimit.OAuthTokenRequests = Int(ctx, s, RateLimitOAuthTokenRequests, cfg.RateLimit.OAuthTokenRequests, 0, 100000)
	cfg.RateLimit.OAuthTokenWindowMinutes = Int(ctx, s, RateLimitOAuthTokenWindowMins, cfg.RateLimit.OAuthTokenWindowMinutes, 1, 100000)
	cfg.RateLimit.SetupRequests = Int(ctx, s, RateLimitSetupRequests, cfg.RateLimit.SetupRequests, 0, 100000)
	cfg.RateLimit.SetupWindowMinutes = Int(ctx, s, RateLimitSetupWindowMinutes, cfg.RateLimit.SetupWindowMinutes, 1, 100000)

	if logger != nil {
		logger.Info("settings applied from the database",
			"registration", cfg.Auth.AllowRegistration,
			"smtp_configured", cfg.SMTP.Host != "",
			"webhook_configured", cfg.Security.WebhookURL != "",
			"metrics_enabled", cfg.Metrics.Enabled,
			"theme", cfg.UI.Theme)
	}
}
