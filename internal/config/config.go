package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

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
	// Enabled and Token are a startup snapshot of Settings → Security.
	Enabled bool   `yaml:"-"`
	Token   string `yaml:"-"`
}

// SecurityConfig holds optional security integrations.
type SecurityConfig struct {
	// WebhookURL is a startup snapshot of Settings → Security. Empty disables
	// the webhook.
	WebhookURL string `yaml:"-"`

	// WebhookSecret is optional. When set, each request body is signed with
	// HMAC-SHA256 under this secret and the digest is sent in the
	// X-Passage-Signature header as "sha256=<hex>".
	WebhookSecret string `yaml:"-"`

	// WebhookTimeoutSeconds bounds one delivery attempt (1–60).
	WebhookTimeoutSeconds int `yaml:"-"`

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
	// Theme is a startup snapshot of the "Server default" theme chosen in
	// Settings → General. Must be one of theme.Names().
	Theme string `yaml:"-"`
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
	// All fields are a startup snapshot of Settings → Rate limits.
	LoginRequests      int `yaml:"-"`
	LoginWindowMinutes int `yaml:"-"`

	ResetRequests      int `yaml:"-"`
	ResetWindowMinutes int `yaml:"-"`

	OAuthTokenRequests      int `yaml:"-"`
	OAuthTokenWindowMinutes int `yaml:"-"`

	SetupRequests      int `yaml:"-"`
	SetupWindowMinutes int `yaml:"-"`

	RegisterRequests      int `yaml:"-"`
	RegisterWindowMinutes int `yaml:"-"`

	MagicLinkRequests      int `yaml:"-"`
	MagicLinkWindowMinutes int `yaml:"-"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	BaseURL string `yaml:"base_url"`
	// TrustedProxies lists the proxy IP addresses or CIDR ranges whose
	// forwarding headers (X-Forwarded-For / X-Real-IP / True-Client-IP) are
	// honored. When nil (omitted), DefaultTrustedProxies() applies. Set to an
	// empty slice ([] in YAML or PASSAGE_SERVER_TRUSTED_PROXIES=none) when
	// Passage is exposed directly without a reverse proxy.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// DefaultTrustedProxies returns the default CIDR ranges trusted as reverse
// proxies: loopback, RFC 1918 private networks, IPv6 ULA, link-local, and
// CGNAT / Tailscale (100.64.0.0/10).
func DefaultTrustedProxies() []string {
	return []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"169.254.0.0/16",
		"fe80::/10",
		"100.64.0.0/10",
	}
}

// EffectiveTrustedProxies returns the configured trusted proxy CIDRs/IPs, or
// DefaultTrustedProxies() when TrustedProxies was left unset (nil). A non-nil
// empty slice returns nil, meaning no proxy headers are trusted.
func (s ServerConfig) EffectiveTrustedProxies() []string {
	if s.TrustedProxies == nil {
		return DefaultTrustedProxies()
	}
	if len(s.TrustedProxies) == 0 {
		return nil
	}
	return s.TrustedProxies
}

// DatabaseConfig holds database settings.
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// SessionConfig holds session settings.
type SessionConfig struct {
	// DurationHours and IdleTimeoutMinutes are a startup snapshot of the
	// matching admin settings (Settings → General). They are not read from the
	// file: the settings table is authoritative.
	DurationHours      int `yaml:"-"`
	IdleTimeoutMinutes int `yaml:"-"`
	// CookieName and CookieSecure describe how the deployment is reached, so
	// they stay in the file.
	CookieName   string `yaml:"cookie_name"`
	CookieSecure bool   `yaml:"cookie_secure"`
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
// SMTPConfig is a startup snapshot of the Email settings. Mail is configured in
// the admin UI, so none of these fields is read from the file.
type SMTPConfig struct {
	Host     string `yaml:"-"`
	Port     int    `yaml:"-"`
	Username string `yaml:"-"`
	Password string `yaml:"-"`
	From     string `yaml:"-"`
	TLS      string `yaml:"-"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	// These are startup snapshots of the matching admin settings. They are not
	// read from the file; the settings table is authoritative.
	AllowRegistration bool `yaml:"-"`
	BcryptCost        int  `yaml:"-"`

	// MaxLoginFailures is the number of consecutive invalid password attempts
	// that locks an account. Zero disables per-account throttling.
	MaxLoginFailures int `yaml:"-"`
	// LockoutMinutes is how long an account stays locked once it reaches
	// MaxLoginFailures. Zero disables per-account throttling.
	LockoutMinutes int `yaml:"-"`

	// RequireMFA is the startup snapshot of the "require two-factor" setting.
	RequireMFA bool `yaml:"-"`
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
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("read config file %q: %w", path, err)
			}
			// File not existing is not an error — env vars and defaults apply.
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parse config file %q: %w", path, err)
			}
		}
	}

	applyEnvOverrides(cfg)
	cfg.Server.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.Server.BaseURL), "/")
	return cfg, nil
}

// Validate checks that all configuration values are within acceptable bounds.
// It uses errors.Join to collect and return all validation errors together.
func (c *Config) Validate() error {
	var errs []error

	// Only bootstrap settings are validated here. Everything an operator edits
	// in the admin UI is validated when the form is submitted (see
	// internal/admin/settings_form.go).
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port))
	}

	if c.Server.BaseURL == "" {
		errs = append(errs, fmt.Errorf("server.base_url is required (e.g. https://auth.example.com)"))
	} else {
		u, err := url.Parse(c.Server.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("server.base_url must be a valid http(s) URL with a host, got %q", c.Server.BaseURL))
		}
	}

	for _, entry := range c.Server.EffectiveTrustedProxies() {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, err := netip.ParsePrefix(entry); err != nil {
				errs = append(errs, fmt.Errorf("server.trusted_proxies contains invalid CIDR %q: %w", entry, err))
			}
		} else if _, err := netip.ParseAddr(entry); err != nil {
			errs = append(errs, fmt.Errorf("server.trusted_proxies contains invalid IP %q: %w", entry, err))
		}
	}

	if c.Database.Path == "" {
		errs = append(errs, fmt.Errorf("database.path must not be empty"))
	}

	if strings.TrimSpace(c.Session.CookieName) == "" {
		errs = append(errs, fmt.Errorf("session.cookie_name must not be empty"))
	}

	switch c.Log.Level {
	case "", "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level must be debug, info, warn, or error, got %q", c.Log.Level))
	}

	switch c.Log.Format {
	case "", "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log.format must be json or text, got %q", c.Log.Format))
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

	if c.CSRF.Key != "" && len(c.CSRF.Key) < 64 {
		errs = append(errs, fmt.Errorf("csrf.key must be at least 64 hex characters (32 random bytes) when set, got %d", len(c.CSRF.Key)))
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
	if v, ok := os.LookupEnv("PASSAGE_SERVER_TRUSTED_PROXIES"); ok {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" || strings.EqualFold(trimmed, "none") {
			cfg.Server.TrustedProxies = []string{}
		} else {
			cfg.Server.TrustedProxies = strings.FieldsFunc(trimmed, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t' || r == '\n'
			})
		}
	}

	// Database
	if v := os.Getenv("PASSAGE_DATABASE_PATH"); v != "" {
		cfg.Database.Path = v
	}

	// Session
	if v := os.Getenv("PASSAGE_SESSION_COOKIE_NAME"); v != "" {
		cfg.Session.CookieName = v
	}
	if v := os.Getenv("PASSAGE_SESSION_COOKIE_SECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Session.CookieSecure = b
		} else {
			fmt.Fprintf(os.Stderr, "passage: warning: ignoring malformed env var %s=%q: %v\n", "PASSAGE_SESSION_COOKIE_SECURE", v, err)
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
	if v := os.Getenv("PASSAGE_SECURITY_ENCRYPTION_KEY"); v != "" {
		cfg.Security.EncryptionKey = v
	}
}
