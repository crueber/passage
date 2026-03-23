package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the Passage server.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Session  SessionConfig
	SMTP     SMTPConfig
	Auth     AuthConfig
	Log      LogConfig
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

// applyEnvOverrides applies PASSAGE_* environment variables on top of cfg.
func applyEnvOverrides(cfg *Config) {
	// Server
	if v := os.Getenv("PASSAGE_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("PASSAGE_SERVER_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = n
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
		}
	}
	if v := os.Getenv("PASSAGE_SESSION_COOKIE_NAME"); v != "" {
		cfg.Session.CookieName = v
	}
	if v := os.Getenv("PASSAGE_SESSION_COOKIE_SECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Session.CookieSecure = b
		}
	}

	// SMTP
	if v := os.Getenv("PASSAGE_SMTP_HOST"); v != "" {
		cfg.SMTP.Host = v
	}
	if v := os.Getenv("PASSAGE_SMTP_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SMTP.Port = n
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
		}
	}
	if v := os.Getenv("PASSAGE_AUTH_BCRYPT_COST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Auth.BcryptCost = n
		}
	}

	// Log
	if v := os.Getenv("PASSAGE_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("PASSAGE_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
}
