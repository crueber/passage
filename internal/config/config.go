package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
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
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// CSRFConfig holds CSRF protection settings.
type CSRFConfig struct {
	// Key is the server-side secret for CSRF token signing.
	// Env: PASSAGE_CSRF_KEY. Should be 32+ random bytes (64+ hex characters),
	// e.g. generated with: openssl rand -hex 32
	// If empty, the ProtectAnonymous middleware uses only the per-session
	// CSRF cookie value as the signing key (still secure, but not server-bound).
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
	DurationHours int    `yaml:"duration_hours"`
	CookieName    string `yaml:"cookie_name"`
	CookieSecure  bool   `yaml:"cookie_secure"`
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
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  true,
		},
		SMTP: SMTPConfig{
			Port: 587,
			TLS:  "starttls",
		},
		Auth: AuthConfig{
			AllowRegistration: true,
			BcryptCost:        12,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
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
	if c.Auth.BcryptCost < 10 || c.Auth.BcryptCost > 31 {
		errs = append(errs, fmt.Errorf("auth.bcrypt_cost must be between 10 and 31, got %d", c.Auth.BcryptCost))
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
}
