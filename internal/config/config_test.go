package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/config"
)

func TestLoad_Defaults(t *testing.T) {
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
