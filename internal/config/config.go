package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
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
	// Settings → Appearance. Must be one of theme.Names().
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

// ProviderConfig configures one upstream OIDC/OAuth identity provider.
//
// Name is a slug used in the login routes (/login/oidc/<name>/start) and must
// be unique. Issuer is an absolute https URL whose
// /.well-known/openid-configuration document names the authorization, token,
// and JWKS endpoints. Scopes defaults to "openid email profile" and must
// include openid.
type ProviderConfig struct {
	Name         string   `yaml:"name"`
	Label        string   `yaml:"label"`
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
	AutoCreate   bool     `yaml:"auto_create"`
}

// DefaultProviderScopes is the scope set used when a provider does not list
// any. Every upstream flow needs openid to receive an id_token.
func DefaultProviderScopes() []string {
	return []string{"openid", "email", "profile"}
}

// providerNameRe constrains provider slugs: lowercase alphanumerics, dash, and
// underscore. The same value is a URL path segment, so anything else would
// need escaping and invites confusion.
var providerNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// AuthConfig holds authentication settings.
type AuthConfig struct {
	// These are startup snapshots of the matching admin settings. They are not
	// read from the file; the settings table is authoritative.
	AllowRegistration bool `yaml:"-"`
	BcryptCost        int  `yaml:"-"`

	// Providers configures upstream OIDC/OAuth identity providers. Each entry
	// adds a sign-in button to the login page. There is deliberately no
	// environment-variable override for this list — a list has no useful
	// single-value env form, so configure it in the YAML file.
	Providers []ProviderConfig `yaml:"providers"`

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

	// Only bootstrap settings are validated here. Everything an operator edits
	// in the admin UI is validated when the form is submitted (see
	// internal/admin/settings_form.go).
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port))
	}

	// Validate upstream identity providers. The provider list is optional; an
	// empty list means the feature stays off and behaves exactly as before.
	seenProviders := make(map[string]bool, len(c.Auth.Providers))
	for i, p := range c.Auth.Providers {
		where := fmt.Sprintf("auth.providers[%d]", i)
		if !providerNameRe.MatchString(p.Name) || len(p.Name) > 64 {
			errs = append(errs, fmt.Errorf("%s.name %q must be a lowercase slug of 1–64 characters ([a-z0-9][a-z0-9_-]*)", where, p.Name))
		}
		if seenProviders[p.Name] {
			errs = append(errs, fmt.Errorf("%s.name %q is duplicated; provider names must be unique", where, p.Name))
		}
		seenProviders[p.Name] = true

		u, err := url.Parse(p.Issuer)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s.issuer is not a valid URL: %w", where, err))
		case !strings.EqualFold(u.Scheme, "https"):
			errs = append(errs, fmt.Errorf("%s.issuer must use https, got scheme %q", where, u.Scheme))
		case u.Host == "":
			errs = append(errs, fmt.Errorf("%s.issuer must include a host, got %q", where, p.Issuer))
		case u.User != nil:
			errs = append(errs, fmt.Errorf("%s.issuer must not include user information", where))
		case u.RawQuery != "" || u.Fragment != "":
			errs = append(errs, fmt.Errorf("%s.issuer must not include a query or fragment", where))
		}
		if p.ClientID == "" {
			errs = append(errs, fmt.Errorf("%s.client_id must not be empty", where))
		}
		if p.ClientSecret == "" {
			errs = append(errs, fmt.Errorf("%s.client_secret must not be empty", where))
		}

		scopes := p.Scopes
		if len(scopes) == 0 {
			scopes = DefaultProviderScopes()
		}
		hasOpenID := false
		for _, scope := range scopes {
			if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
				errs = append(errs, fmt.Errorf("%s.scopes contains an invalid scope %q", where, scope))
				continue
			}
			if scope == "openid" {
				hasOpenID = true
			}
		}
		if !hasOpenID {
			errs = append(errs, fmt.Errorf("%s.scopes must include \"openid\"", where))
		}
	}
	if len(c.Auth.Providers) > 0 && c.Server.BaseURL == "" {
		errs = append(errs, fmt.Errorf("server.base_url is required when auth.providers is configured (it builds the OAuth redirect URI)"))
	}

	if c.Database.Path == "" {
		errs = append(errs, fmt.Errorf("database.path must not be empty"))
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

	// SMTP

	// Auth

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

	// UI

	// Metrics

	// RateLimit
}
