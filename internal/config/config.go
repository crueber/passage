package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/theme"
)

// Config holds all configuration for the Passage server.
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Session   SessionConfig
	SMTP      SMTPConfig
	Auth      AuthConfig
	Log       LogConfig
	CSRF      CSRFConfig
	Security  SecurityConfig  `yaml:"security"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	UI        UIConfig        `yaml:"ui"`
	Metrics   MetricsConfig   `yaml:"metrics"`
}

// MetricsConfig holds the Prometheus endpoint settings.
type MetricsConfig struct {
	// Enabled serves GET /metrics. It defaults to true so an operator who has
	// not thought about metrics still gets them; setting it to false makes the
	// endpoint answer 404.
	// Env: PASSAGE_METRICS_ENABLED.
	Enabled bool `yaml:"enabled"`

	// Token, when set, requires scrapes to send
	// "Authorization: Bearer <token>". Optional: leave empty when the endpoint
	// is reachable only from a trusted network or an authenticating proxy.
	// The token is never logged.
	// Env: PASSAGE_METRICS_TOKEN.
	Token string `yaml:"token"`
}

// SecurityConfig holds optional security integrations.
type SecurityConfig struct {
	// WebhookURL is an HTTP endpoint that receives every recorded
	// authentication event as a JSON POST. Empty disables the webhook.
	// Env: PASSAGE_SECURITY_WEBHOOK_URL.
	WebhookURL string `yaml:"webhook_url"`

	// WebhookSecret is optional. When set, each request body is signed with
	// HMAC-SHA256 under this secret and the digest is sent in the
	// X-Passage-Signature header as "sha256=<hex>".
	// Env: PASSAGE_SECURITY_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"webhook_secret"`

	// WebhookTimeoutSeconds bounds one delivery attempt.
	// Default 5, valid range 1–60.
	// Env: PASSAGE_SECURITY_WEBHOOK_TIMEOUT_SECONDS.
	WebhookTimeoutSeconds int `yaml:"webhook_timeout_seconds"`

	// EncryptionKey is the AES-256-GCM key that encrypts TOTP secrets at rest,
	// as 64 hex characters or the base64 encoding of 32 bytes (for example
	// `openssl rand -hex 32`). Optional: when empty, a key file named
	// <database.path>.key is created next to the database on first use, mode
	// 0600. Either way the key must stay stable across restarts — losing it
	// makes every enrolled TOTP secret unreadable and each affected user needs
	// an admin MFA reset.
	// Env: PASSAGE_SECURITY_ENCRYPTION_KEY.
	EncryptionKey string `yaml:"encryption_key"`
}

// UIConfig holds web UI presentation settings.
type UIConfig struct {
	// Theme is the default colour theme served to browsers and used by the
	// compiled fallback stylesheet. Must be one of theme.Names().
	// Env: PASSAGE_UI_THEME.
	Theme string `yaml:"theme"`
}

// CSRFConfig holds CSRF protection settings.
type CSRFConfig struct {
	// Key is the server-side secret for CSRF token signing.
	// Env: PASSAGE_CSRF_KEY. Should be 32+ random bytes (64+ hex characters),
	// e.g. generated with: openssl rand -hex 32
	// If empty, run() generates an ephemeral key at startup, so anonymous CSRF
	// tokens are always server-bound. Set an explicit key for multi-instance
	// deployments (and to keep anonymous CSRF cookies valid across restarts).
	Key string `yaml:"key"`
}

// RateLimitConfig holds sliding-window rate limiter settings.
// Each limiter is configured independently with a max request count and a
// window duration in minutes.
type RateLimitConfig struct {
	// Login controls the login endpoint rate limit.
	// Env: PASSAGE_RATELIMIT_LOGIN_REQUESTS / PASSAGE_RATELIMIT_LOGIN_WINDOW_MINUTES
	LoginRequests      int `yaml:"login_requests"`
	LoginWindowMinutes int `yaml:"login_window_minutes"`

	// Reset controls the password-reset endpoint rate limit.
	// Env: PASSAGE_RATELIMIT_RESET_REQUESTS / PASSAGE_RATELIMIT_RESET_WINDOW_MINUTES
	ResetRequests      int `yaml:"reset_requests"`
	ResetWindowMinutes int `yaml:"reset_window_minutes"`

	// OAuthToken controls the OAuth /token endpoint rate limit.
	// Env: PASSAGE_RATELIMIT_OAUTH_TOKEN_REQUESTS / PASSAGE_RATELIMIT_OAUTH_TOKEN_WINDOW_MINUTES
	OAuthTokenRequests      int `yaml:"oauth_token_requests"`
	OAuthTokenWindowMinutes int `yaml:"oauth_token_window_minutes"`

	// Setup controls the initial-setup endpoint rate limit.
	// Env: PASSAGE_RATELIMIT_SETUP_REQUESTS / PASSAGE_RATELIMIT_SETUP_WINDOW_MINUTES
	SetupRequests      int `yaml:"setup_requests"`
	SetupWindowMinutes int `yaml:"setup_window_minutes"`

	// Register controls the self-service registration endpoint rate limit.
	// Env: PASSAGE_RATELIMIT_REGISTER_REQUESTS / PASSAGE_RATELIMIT_REGISTER_WINDOW_MINUTES
	RegisterRequests      int `yaml:"register_requests"`
	RegisterWindowMinutes int `yaml:"register_window_minutes"`

	// MagicLink controls the magic-link request endpoint rate limit (each
	// request triggers an outbound email).
	// Env: PASSAGE_RATELIMIT_MAGIC_LINK_REQUESTS / PASSAGE_RATELIMIT_MAGIC_LINK_WINDOW_MINUTES
	MagicLinkRequests      int `yaml:"magic_link_requests"`
	MagicLinkWindowMinutes int `yaml:"magic_link_window_minutes"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	BaseURL string `yaml:"base_url"`
}

// DatabaseConfig holds database settings.
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// SessionConfig holds session settings.
type SessionConfig struct {
	DurationHours int `yaml:"duration_hours"`
	// IdleTimeoutMinutes closes a session that has not been used for this many
	// minutes, independent of the absolute DurationHours. Zero (the default)
	// disables the idle timeout.
	// Env: PASSAGE_SESSION_IDLE_TIMEOUT_MINUTES.
	IdleTimeoutMinutes int    `yaml:"idle_timeout_minutes"`
	CookieName         string `yaml:"cookie_name"`
	CookieSecure       bool   `yaml:"cookie_secure"`
}

// IdleTimeout returns the configured idle window as a duration. A zero or
// negative value means the idle timeout is disabled.
func (s SessionConfig) IdleTimeout() time.Duration {
	if s.IdleTimeoutMinutes <= 0 {
		return 0
	}
	return time.Duration(s.IdleTimeoutMinutes) * time.Minute
}

// EffectiveCookieName returns the session cookie name, applying the __Host-
// prefix when secure cookies are enabled. The prefix (a browser-enforced
// invariant: Secure attribute, no Domain attribute, Path=/) blocks
// sibling-subdomain cookie tossing that could shadow the session or CSRF
// cookies. Clearing and setting code MUST go through this method so readers
// and writers always agree on the name.
func (s SessionConfig) EffectiveCookieName() string {
	if s.CookieSecure {
		return "__Host-" + s.CookieName
	}
	return s.CookieName
}

// SMTPConfig holds email/SMTP settings.
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	TLS      string `yaml:"tls"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	AllowRegistration bool `yaml:"allow_registration"`
	BcryptCost        int  `yaml:"bcrypt_cost"`

	// MaxLoginFailures is the number of consecutive invalid password attempts
	// that locks an account. Zero disables per-account throttling.
	// Env: PASSAGE_AUTH_MAX_LOGIN_FAILURES.
	MaxLoginFailures int `yaml:"max_login_failures"`
	// LockoutMinutes is how long an account stays locked once it reaches
	// MaxLoginFailures. Zero disables per-account throttling.
	// Env: PASSAGE_AUTH_LOCKOUT_MINUTES.
	LockoutMinutes int `yaml:"lockout_minutes"`

	// RequireMFA makes two-factor authentication mandatory: a signed-in user
	// without a completed TOTP enrollment is sent to /mfa/setup until they
	// enrol. It is only a default — an explicit auth_require_mfa value in the
	// settings store (Settings → Authentication methods) wins over it.
	// Env: PASSAGE_AUTH_REQUIRE_MFA.
	RequireMFA bool `yaml:"require_mfa"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// defaults returns a Config populated with default values.
func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Database: DatabaseConfig{
			Path: "passage.db",
		},
		Session: SessionConfig{
			DurationHours:      24,
			IdleTimeoutMinutes: 0,
			CookieName:         "passage_session",
			CookieSecure:       true,
		},
		SMTP: SMTPConfig{
			Port: 587,
			TLS:  "starttls",
		},
		Auth: AuthConfig{
			AllowRegistration: true,
			BcryptCost:        12,
			MaxLoginFailures:  5,
			LockoutMinutes:    15,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Security: SecurityConfig{
			WebhookTimeoutSeconds: 5,
		},
		RateLimit: RateLimitConfig{
			LoginRequests:           10,
			LoginWindowMinutes:      15,
			ResetRequests:           5,
			ResetWindowMinutes:      60,
			OAuthTokenRequests:      20,
			OAuthTokenWindowMinutes: 1,
			SetupRequests:           5,
			SetupWindowMinutes:      60,
			RegisterRequests:        10,
			RegisterWindowMinutes:   60,
			MagicLinkRequests:       5,
			MagicLinkWindowMinutes:  60,
		},
		UI: UIConfig{
			Theme: theme.Default(),
		},
		Metrics: MetricsConfig{
			Enabled: true,
		},
	}
}

// Load loads configuration from the given YAML file path and then applies
// any PASSAGE_* environment variable overrides.
//
// If path is empty or the file does not exist, only defaults and environment
// variables are used — that is not an error.
func Load(path string) (*Config, error) {
	cfg := defaults()

	if path != "" {
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read config file %q: %w", path, err)
			}
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parse config file %q: %w", path, err)
			}
		}
		// File not existing is not an error — env vars and defaults apply.
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

// Validate checks that all configuration values are within acceptable bounds.
// It uses errors.Join to collect and return all validation errors together.
func (c *Config) Validate() error {
	var errs []error

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port))
	}
	if c.Session.DurationHours <= 0 {
		errs = append(errs, fmt.Errorf("session.duration_hours must be positive, got %d", c.Session.DurationHours))
	}
	if c.Session.IdleTimeoutMinutes < 0 {
		errs = append(errs, fmt.Errorf("session.idle_timeout_minutes must be zero or positive, got %d", c.Session.IdleTimeoutMinutes))
	}
	if c.Auth.BcryptCost < 10 || c.Auth.BcryptCost > 31 {
		errs = append(errs, fmt.Errorf("auth.bcrypt_cost must be between 10 and 31, got %d", c.Auth.BcryptCost))
	}
	if c.Auth.MaxLoginFailures < 0 {
		errs = append(errs, fmt.Errorf("auth.max_login_failures must be zero or positive, got %d", c.Auth.MaxLoginFailures))
	}
	if c.Auth.LockoutMinutes < 0 {
		errs = append(errs, fmt.Errorf("auth.lockout_minutes must be zero or positive, got %d", c.Auth.LockoutMinutes))
	}
	if c.Database.Path == "" {
		errs = append(errs, fmt.Errorf("database.path must not be empty"))
	}

	// Validate SMTP TLS mode only when SMTP is configured.
	if c.SMTP.Host != "" {
		switch c.SMTP.TLS {
		case "tls", "starttls", "none":
			// valid
		default:
			errs = append(errs, fmt.Errorf("smtp.tls must be one of \"tls\", \"starttls\", or \"none\", got %q", c.SMTP.TLS))
		}
	}

	// Validate CSRF key length if explicitly set.
	if c.CSRF.Key != "" && len(c.CSRF.Key) < 64 {
		errs = append(errs, fmt.Errorf("csrf.key must be at least 64 hex characters (32 random bytes) when set, got %d", len(c.CSRF.Key)))
	}

	// Validate the security webhook. An empty URL disables the feature; a
	// configured endpoint must be a usable http(s) URL. The timeout is always
	// checked so a typo is caught even while the webhook is disabled.
	if c.Security.WebhookURL != "" {
		u, err := url.Parse(c.Security.WebhookURL)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("security.webhook_url is not a valid URL: %w", err))
		case u.Scheme != "http" && u.Scheme != "https":
			errs = append(errs, fmt.Errorf("security.webhook_url must use http or https, got scheme %q", u.Scheme))
		case u.Host == "":
			errs = append(errs, fmt.Errorf("security.webhook_url must include a host, got %q", c.Security.WebhookURL))
		}
	}
	if c.Security.WebhookTimeoutSeconds < 1 || c.Security.WebhookTimeoutSeconds > 60 {
		errs = append(errs, fmt.Errorf("security.webhook_timeout_seconds must be between 1 and 60, got %d", c.Security.WebhookTimeoutSeconds))
	}

	// Validate the secret-encryption key format if explicitly set. An empty
	// value is valid: the key file next to the database is used instead.
	// ParseKey is the same decoder the server uses, so a value that passes here
	// cannot fail at startup.
	if c.Security.EncryptionKey != "" {
		if _, err := mfa.ParseKey(c.Security.EncryptionKey); err != nil {
			errs = append(errs, fmt.Errorf("security.encryption_key is invalid: %w", err))
		}
	}

	// Validate the UI theme against the registry.
	if _, ok := theme.Lookup(c.UI.Theme); !ok {
		errs = append(errs, fmt.Errorf("ui.theme %q is not a known theme (valid: %s)", c.UI.Theme, strings.Join(theme.Names(), ", ")))
	}

	// A metrics token is presented as a Bearer credential, so whitespace or
	// control characters would make it unusable. The message never includes the
	// value — the token is a secret.
	if c.Metrics.Token != "" {
		if strings.ContainsFunc(c.Metrics.Token, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) {
			errs = append(errs, fmt.Errorf("metrics.token must not contain whitespace or control characters"))
		}
	}

	// Validate rate limit values — all must be positive.
	rl := c.RateLimit
	if rl.LoginRequests <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.login_requests must be positive, got %d", rl.LoginRequests))
	}
	if rl.LoginWindowMinutes <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.login_window_minutes must be positive, got %d", rl.LoginWindowMinutes))
	}
	if rl.ResetRequests <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.reset_requests must be positive, got %d", rl.ResetRequests))
	}
	if rl.ResetWindowMinutes <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.reset_window_minutes must be positive, got %d", rl.ResetWindowMinutes))
	}
	if rl.OAuthTokenRequests <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.oauth_token_requests must be positive, got %d", rl.OAuthTokenRequests))
	}
	if rl.OAuthTokenWindowMinutes <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.oauth_token_window_minutes must be positive, got %d", rl.OAuthTokenWindowMinutes))
	}
	if rl.RegisterRequests <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.register_requests must be positive, got %d", rl.RegisterRequests))
	}
	if rl.RegisterWindowMinutes <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.register_window_minutes must be positive, got %d", rl.RegisterWindowMinutes))
	}
	if rl.MagicLinkRequests <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.magic_link_requests must be positive, got %d", rl.MagicLinkRequests))
	}
	if rl.MagicLinkWindowMinutes <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.magic_link_window_minutes must be positive, got %d", rl.MagicLinkWindowMinutes))
	}
	if rl.SetupRequests <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.setup_requests must be positive, got %d", rl.SetupRequests))
	}
	if rl.SetupWindowMinutes <= 0 {
		errs = append(errs, fmt.Errorf("ratelimit.setup_window_minutes must be positive, got %d", rl.SetupWindowMinutes))
	}

	return errors.Join(errs...)
}

// applyEnvOverrides applies PASSAGE_* environment variables on top of cfg.
func applyEnvOverrides(cfg *Config) {
	// Server
	if v := os.Getenv("PASSAGE_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("PASSAGE_SERVER_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_SERVER_PORT", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_SERVER_BASE_URL"); v != "" {
		cfg.Server.BaseURL = v
	}

	// Database
	if v := os.Getenv("PASSAGE_DATABASE_PATH"); v != "" {
		cfg.Database.Path = v
	}

	// Session
	if v := os.Getenv("PASSAGE_SESSION_DURATION_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Session.DurationHours = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_SESSION_DURATION_HOURS", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_SESSION_COOKIE_NAME"); v != "" {
		cfg.Session.CookieName = v
	}
	if v := os.Getenv("PASSAGE_SESSION_IDLE_TIMEOUT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Session.IdleTimeoutMinutes = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_SESSION_IDLE_TIMEOUT_MINUTES", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_SESSION_COOKIE_SECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Session.CookieSecure = b
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_SESSION_COOKIE_SECURE", v, err)
		}
	}

	// SMTP
	if v := os.Getenv("PASSAGE_SMTP_HOST"); v != "" {
		cfg.SMTP.Host = v
	}
	if v := os.Getenv("PASSAGE_SMTP_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SMTP.Port = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_SMTP_PORT", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_SMTP_USERNAME"); v != "" {
		cfg.SMTP.Username = v
	}
	if v := os.Getenv("PASSAGE_SMTP_PASSWORD"); v != "" {
		cfg.SMTP.Password = v
	}
	if v := os.Getenv("PASSAGE_SMTP_FROM"); v != "" {
		cfg.SMTP.From = v
	}
	if v := os.Getenv("PASSAGE_SMTP_TLS"); v != "" {
		cfg.SMTP.TLS = v
	}

	// Auth
	if v := os.Getenv("PASSAGE_AUTH_ALLOW_REGISTRATION"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Auth.AllowRegistration = b
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_AUTH_ALLOW_REGISTRATION", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_AUTH_BCRYPT_COST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Auth.BcryptCost = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_AUTH_BCRYPT_COST", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_AUTH_MAX_LOGIN_FAILURES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Auth.MaxLoginFailures = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_AUTH_MAX_LOGIN_FAILURES", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_AUTH_LOCKOUT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Auth.LockoutMinutes = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_AUTH_LOCKOUT_MINUTES", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_AUTH_REQUIRE_MFA"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Auth.RequireMFA = b
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_AUTH_REQUIRE_MFA", v, err)
		}
	}

	// Log
	if v := os.Getenv("PASSAGE_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("PASSAGE_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}

	// CSRF
	if v := os.Getenv("PASSAGE_CSRF_KEY"); v != "" {
		cfg.CSRF.Key = v
	}

	// Security
	if v := os.Getenv("PASSAGE_SECURITY_WEBHOOK_URL"); v != "" {
		cfg.Security.WebhookURL = v
	}
	if v := os.Getenv("PASSAGE_SECURITY_WEBHOOK_SECRET"); v != "" {
		cfg.Security.WebhookSecret = v
	}
	if v := os.Getenv("PASSAGE_SECURITY_WEBHOOK_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Security.WebhookTimeoutSeconds = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_SECURITY_WEBHOOK_TIMEOUT_SECONDS", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_SECURITY_ENCRYPTION_KEY"); v != "" {
		cfg.Security.EncryptionKey = v
	}

	// UI
	if v := os.Getenv("PASSAGE_UI_THEME"); v != "" {
		cfg.UI.Theme = v
	}

	// Metrics
	if v := os.Getenv("PASSAGE_METRICS_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Metrics.Enabled = b
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_METRICS_ENABLED", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_METRICS_TOKEN"); v != "" {
		cfg.Metrics.Token = v
	}

	// RateLimit
	if v := os.Getenv("PASSAGE_RATELIMIT_LOGIN_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.LoginRequests = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_LOGIN_REQUESTS", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_LOGIN_WINDOW_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.LoginWindowMinutes = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_LOGIN_WINDOW_MINUTES", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_RESET_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.ResetRequests = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_RESET_REQUESTS", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_RESET_WINDOW_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.ResetWindowMinutes = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_RESET_WINDOW_MINUTES", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_OAUTH_TOKEN_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.OAuthTokenRequests = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_OAUTH_TOKEN_REQUESTS", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_OAUTH_TOKEN_WINDOW_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.OAuthTokenWindowMinutes = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_OAUTH_TOKEN_WINDOW_MINUTES", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_SETUP_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.SetupRequests = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_SETUP_REQUESTS", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_SETUP_WINDOW_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.SetupWindowMinutes = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_SETUP_WINDOW_MINUTES", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_REGISTER_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.RegisterRequests = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_REGISTER_REQUESTS", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_REGISTER_WINDOW_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.RegisterWindowMinutes = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_REGISTER_WINDOW_MINUTES", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_MAGIC_LINK_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.MagicLinkRequests = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_MAGIC_LINK_REQUESTS", v, err)
		}
	}
	if v := os.Getenv("PASSAGE_RATELIMIT_MAGIC_LINK_WINDOW_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.MagicLinkWindowMinutes = n
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_RATELIMIT_MAGIC_LINK_WINDOW_MINUTES", v, err)
		}
	}
}
