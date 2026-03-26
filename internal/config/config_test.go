package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/config"
)

func TestLoad_Defaults(t *testing.T) {
	t.Parallel()
	// Load with no file — should get all defaults.
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load(%q): unexpected error: %v", "", err)
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Server.Host", cfg.Server.Host, "0.0.0.0"},
		{"Server.Port", cfg.Server.Port, 8080},
		{"Server.BaseURL", cfg.Server.BaseURL, ""},
		{"Database.Path", cfg.Database.Path, "passage.db"},
		{"Session.DurationHours", cfg.Session.DurationHours, 24},
		{"Session.CookieName", cfg.Session.CookieName, "passage_session"},
		{"Session.CookieSecure", cfg.Session.CookieSecure, true},
		{"SMTP.Port", cfg.SMTP.Port, 587},
		{"SMTP.TLS", cfg.SMTP.TLS, "starttls"},
		{"Auth.AllowRegistration", cfg.Auth.AllowRegistration, true},
		{"Auth.BcryptCost", cfg.Auth.BcryptCost, 12},
		{"Log.Level", cfg.Log.Level, "info"},
		{"Log.Format", cfg.Log.Format, "json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v; want %v", tt.got, tt.want)
			}
		})
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	// NOTE: t.Parallel() is intentionally omitted here. This test uses
	// t.Setenv to mutate environment variables, and Go's testing package
	// (since Go 1.25) panics if t.Setenv is called after t.Parallel().
	// Serial execution is correct for env-var mutation tests.

	// Set a few env vars and verify they override defaults.
	envVars := map[string]string{
		"PASSAGE_SERVER_HOST":           "127.0.0.1",
		"PASSAGE_SERVER_PORT":           "9090",
		"PASSAGE_DATABASE_PATH":         "/tmp/test.db",
		"PASSAGE_LOG_LEVEL":             "debug",
		"PASSAGE_LOG_FORMAT":            "text",
		"PASSAGE_AUTH_BCRYPT_COST":      "14",
		"PASSAGE_SESSION_COOKIE_SECURE": "false",
	}

	// Set env vars and restore them after the test.
	for k, v := range envVars {
		t.Setenv(k, v)
	}

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load(%q): unexpected error: %v", "", err)
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Server.Host", cfg.Server.Host, "127.0.0.1"},
		{"Server.Port", cfg.Server.Port, 9090},
		{"Database.Path", cfg.Database.Path, "/tmp/test.db"},
		{"Log.Level", cfg.Log.Level, "debug"},
		{"Log.Format", cfg.Log.Format, "text"},
		{"Auth.BcryptCost", cfg.Auth.BcryptCost, 14},
		{"Session.CookieSecure", cfg.Session.CookieSecure, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v; want %v", tt.got, tt.want)
			}
		})
	}
}

func TestLoad_YAMLFile(t *testing.T) {
	t.Parallel()
	// Write a temporary YAML config file.
	yaml := `
server:
  host: "192.168.1.10"
  port: 7777
  base_url: "https://auth.home.lab"
database:
  path: "/data/passage.db"
session:
  duration_hours: 48
  cookie_name: "my_session"
  cookie_secure: false
smtp:
  host: "mail.home.lab"
  port: 465
  username: "passage"
  password: "secret"
  from: "Passage <passage@home.lab>"
  tls: "tls"
auth:
  allow_registration: false
  bcrypt_cost: 10
log:
  level: "warn"
  format: "text"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "passage.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%q): unexpected error: %v", path, err)
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Server.Host", cfg.Server.Host, "192.168.1.10"},
		{"Server.Port", cfg.Server.Port, 7777},
		{"Server.BaseURL", cfg.Server.BaseURL, "https://auth.home.lab"},
		{"Database.Path", cfg.Database.Path, "/data/passage.db"},
		{"Session.DurationHours", cfg.Session.DurationHours, 48},
		{"Session.CookieName", cfg.Session.CookieName, "my_session"},
		{"Session.CookieSecure", cfg.Session.CookieSecure, false},
		{"SMTP.Host", cfg.SMTP.Host, "mail.home.lab"},
		{"SMTP.Port", cfg.SMTP.Port, 465},
		{"SMTP.Username", cfg.SMTP.Username, "passage"},
		{"SMTP.Password", cfg.SMTP.Password, "secret"},
		{"SMTP.From", cfg.SMTP.From, "Passage <passage@home.lab>"},
		{"SMTP.TLS", cfg.SMTP.TLS, "tls"},
		{"Auth.AllowRegistration", cfg.Auth.AllowRegistration, false},
		{"Auth.BcryptCost", cfg.Auth.BcryptCost, 10},
		{"Log.Level", cfg.Log.Level, "warn"},
		{"Log.Format", cfg.Log.Format, "text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v; want %v", tt.got, tt.want)
			}
		})
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(":\tinvalid: [yaml\n"), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
	if !strings.Contains(err.Error(), "parse config file") {
		t.Errorf("expected error to contain %q, got: %v", "parse config file", err)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	validCfg := func() *config.Config {
		cfg, _ := config.Load("")
		return cfg
	}

	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr bool
	}{
		{
			name:    "valid config passes",
			mutate:  func(c *config.Config) {},
			wantErr: false,
		},
		{
			name:    "bcrypt_cost below 10 fails",
			mutate:  func(c *config.Config) { c.Auth.BcryptCost = 9 },
			wantErr: true,
		},
		{
			name:    "bcrypt_cost above 31 fails",
			mutate:  func(c *config.Config) { c.Auth.BcryptCost = 32 },
			wantErr: true,
		},
		{
			name:    "port zero fails",
			mutate:  func(c *config.Config) { c.Server.Port = 0 },
			wantErr: true,
		},
		{
			name:    "port above 65535 fails",
			mutate:  func(c *config.Config) { c.Server.Port = 65536 },
			wantErr: true,
		},
		{
			name:    "duration_hours zero fails",
			mutate:  func(c *config.Config) { c.Session.DurationHours = 0 },
			wantErr: true,
		},
		{
			name:    "duration_hours negative fails",
			mutate:  func(c *config.Config) { c.Session.DurationHours = -1 },
			wantErr: true,
		},
		{
			name:    "empty database path fails",
			mutate:  func(c *config.Config) { c.Database.Path = "" },
			wantErr: true,
		},
		{
			name: "smtp tls=starttls with host passes",
			mutate: func(c *config.Config) {
				c.SMTP.Host = "mail.example.com"
				c.SMTP.TLS = "starttls"
			},
			wantErr: false,
		},
		{
			name: "smtp tls=tls with host passes",
			mutate: func(c *config.Config) {
				c.SMTP.Host = "mail.example.com"
				c.SMTP.TLS = "tls"
			},
			wantErr: false,
		},
		{
			name: "smtp tls=none with host passes",
			mutate: func(c *config.Config) {
				c.SMTP.Host = "mail.example.com"
				c.SMTP.TLS = "none"
			},
			wantErr: false,
		},
		{
			name: "smtp tls=ssl with host fails",
			mutate: func(c *config.Config) {
				c.SMTP.Host = "mail.example.com"
				c.SMTP.TLS = "ssl"
			},
			wantErr: true,
		},
		{
			name: "smtp tls empty with host fails",
			mutate: func(c *config.Config) {
				c.SMTP.Host = "mail.example.com"
				c.SMTP.TLS = ""
			},
			wantErr: true,
		},
		{
			name: "smtp tls=ssl with no host passes (smtp not configured)",
			mutate: func(c *config.Config) {
				c.SMTP.Host = ""
				c.SMTP.TLS = "ssl"
			},
			wantErr: false,
		},
		// RateLimit validation
		{
			name:    "ratelimit login_requests zero fails",
			mutate:  func(c *config.Config) { c.RateLimit.LoginRequests = 0 },
			wantErr: true,
		},
		{
			name:    "ratelimit login_requests negative fails",
			mutate:  func(c *config.Config) { c.RateLimit.LoginRequests = -1 },
			wantErr: true,
		},
		{
			name:    "ratelimit login_window_minutes zero fails",
			mutate:  func(c *config.Config) { c.RateLimit.LoginWindowMinutes = 0 },
			wantErr: true,
		},
		{
			name:    "ratelimit reset_requests zero fails",
			mutate:  func(c *config.Config) { c.RateLimit.ResetRequests = 0 },
			wantErr: true,
		},
		{
			name:    "ratelimit reset_window_minutes zero fails",
			mutate:  func(c *config.Config) { c.RateLimit.ResetWindowMinutes = 0 },
			wantErr: true,
		},
		{
			name:    "ratelimit oauth_token_requests zero fails",
			mutate:  func(c *config.Config) { c.RateLimit.OAuthTokenRequests = 0 },
			wantErr: true,
		},
		{
			name:    "ratelimit oauth_token_window_minutes zero fails",
			mutate:  func(c *config.Config) { c.RateLimit.OAuthTokenWindowMinutes = 0 },
			wantErr: true,
		},
		{
			name:    "ratelimit setup_requests zero fails",
			mutate:  func(c *config.Config) { c.RateLimit.SetupRequests = 0 },
			wantErr: true,
		},
		{
			name:    "ratelimit setup_window_minutes zero fails",
			mutate:  func(c *config.Config) { c.RateLimit.SetupWindowMinutes = 0 },
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validCfg()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoad_RateLimitDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load(%q): unexpected error: %v", "", err)
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"RateLimit.LoginRequests", cfg.RateLimit.LoginRequests, 10},
		{"RateLimit.LoginWindowMinutes", cfg.RateLimit.LoginWindowMinutes, 15},
		{"RateLimit.ResetRequests", cfg.RateLimit.ResetRequests, 5},
		{"RateLimit.ResetWindowMinutes", cfg.RateLimit.ResetWindowMinutes, 60},
		{"RateLimit.OAuthTokenRequests", cfg.RateLimit.OAuthTokenRequests, 20},
		{"RateLimit.OAuthTokenWindowMinutes", cfg.RateLimit.OAuthTokenWindowMinutes, 1},
		{"RateLimit.SetupRequests", cfg.RateLimit.SetupRequests, 5},
		{"RateLimit.SetupWindowMinutes", cfg.RateLimit.SetupWindowMinutes, 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v; want %v", tt.got, tt.want)
			}
		})
	}
}

func TestLoad_RateLimitYAML(t *testing.T) {
	t.Parallel()
	yaml := `
rate_limit:
  login_requests: 20
  login_window_minutes: 5
  reset_requests: 3
  reset_window_minutes: 30
  oauth_token_requests: 50
  oauth_token_window_minutes: 2
  setup_requests: 2
  setup_window_minutes: 120
`
	dir := t.TempDir()
	path := filepath.Join(dir, "passage.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%q): unexpected error: %v", path, err)
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"RateLimit.LoginRequests", cfg.RateLimit.LoginRequests, 20},
		{"RateLimit.LoginWindowMinutes", cfg.RateLimit.LoginWindowMinutes, 5},
		{"RateLimit.ResetRequests", cfg.RateLimit.ResetRequests, 3},
		{"RateLimit.ResetWindowMinutes", cfg.RateLimit.ResetWindowMinutes, 30},
		{"RateLimit.OAuthTokenRequests", cfg.RateLimit.OAuthTokenRequests, 50},
		{"RateLimit.OAuthTokenWindowMinutes", cfg.RateLimit.OAuthTokenWindowMinutes, 2},
		{"RateLimit.SetupRequests", cfg.RateLimit.SetupRequests, 2},
		{"RateLimit.SetupWindowMinutes", cfg.RateLimit.SetupWindowMinutes, 120},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v; want %v", tt.got, tt.want)
			}
		})
	}
}

func TestLoad_RateLimitEnvOverride(t *testing.T) {
	// NOTE: t.Parallel() intentionally omitted — t.Setenv mutates env vars.

	envVars := map[string]string{
		"PASSAGE_RATELIMIT_LOGIN_REQUESTS":             "30",
		"PASSAGE_RATELIMIT_LOGIN_WINDOW_MINUTES":       "10",
		"PASSAGE_RATELIMIT_RESET_REQUESTS":             "7",
		"PASSAGE_RATELIMIT_RESET_WINDOW_MINUTES":       "45",
		"PASSAGE_RATELIMIT_OAUTH_TOKEN_REQUESTS":       "100",
		"PASSAGE_RATELIMIT_OAUTH_TOKEN_WINDOW_MINUTES": "3",
		"PASSAGE_RATELIMIT_SETUP_REQUESTS":             "1",
		"PASSAGE_RATELIMIT_SETUP_WINDOW_MINUTES":       "90",
	}
	for k, v := range envVars {
		t.Setenv(k, v)
	}

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load(%q): unexpected error: %v", "", err)
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"RateLimit.LoginRequests", cfg.RateLimit.LoginRequests, 30},
		{"RateLimit.LoginWindowMinutes", cfg.RateLimit.LoginWindowMinutes, 10},
		{"RateLimit.ResetRequests", cfg.RateLimit.ResetRequests, 7},
		{"RateLimit.ResetWindowMinutes", cfg.RateLimit.ResetWindowMinutes, 45},
		{"RateLimit.OAuthTokenRequests", cfg.RateLimit.OAuthTokenRequests, 100},
		{"RateLimit.OAuthTokenWindowMinutes", cfg.RateLimit.OAuthTokenWindowMinutes, 3},
		{"RateLimit.SetupRequests", cfg.RateLimit.SetupRequests, 1},
		{"RateLimit.SetupWindowMinutes", cfg.RateLimit.SetupWindowMinutes, 90},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v; want %v", tt.got, tt.want)
			}
		})
	}
}
