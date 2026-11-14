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
		{"Session.IdleTimeoutMinutes", cfg.Session.IdleTimeoutMinutes, 0},
		{"Session.CookieName", cfg.Session.CookieName, "passage_session"},
		{"Session.CookieSecure", cfg.Session.CookieSecure, true},
		{"SMTP.Port", cfg.SMTP.Port, 587},
		{"SMTP.TLS", cfg.SMTP.TLS, "starttls"},
		{"Auth.AllowRegistration", cfg.Auth.AllowRegistration, true},
		{"Auth.BcryptCost", cfg.Auth.BcryptCost, 12},
		{"Auth.MaxLoginFailures", cfg.Auth.MaxLoginFailures, 5},
		{"Auth.LockoutMinutes", cfg.Auth.LockoutMinutes, 15},
		{"Log.Level", cfg.Log.Level, "info"},
		{"Log.Format", cfg.Log.Format, "json"},
		{"UI.Theme", cfg.UI.Theme, "cool-slate"},
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
  cookie_name: "my_session"
  cookie_secure: false
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
		{"Session.CookieName", cfg.Session.CookieName, "my_session"},
		{"Session.CookieSecure", cfg.Session.CookieSecure, false},
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
			name:   "valid config passes",
			mutate: func(c *config.Config) {},
		},
		{
			name:    "port zero fails",
			mutate:  func(c *config.Config) { c.Server.Port = 0 },
			wantErr: true,
		},
		{
			name:    "port above 65535 fails",
			mutate:  func(c *config.Config) { c.Server.Port = 70000 },
			wantErr: true,
		},
		{
			name:    "empty database path fails",
			mutate:  func(c *config.Config) { c.Database.Path = "" },
			wantErr: true,
		},
		{
			name:   "encryption key unset is valid (key file next to the database)",
			mutate: func(c *config.Config) { c.Security.EncryptionKey = "" },
		},
		{
			name: "encryption key as 64 hex characters is valid",
			mutate: func(c *config.Config) {
				c.Security.EncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			},
		},
		{
			name:    "garbage encryption key fails",
			mutate:  func(c *config.Config) { c.Security.EncryptionKey = "not-a-key" },
			wantErr: true,
		},
		{
			name:    "short csrf key fails",
			mutate:  func(c *config.Config) { c.CSRF.Key = "short" },
			wantErr: true,
		},
		{
			name:   "csrf key of 64 hex characters passes",
			mutate: func(c *config.Config) { c.CSRF.Key = strings.Repeat("ab", 32) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validCfg()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
func TestEffectiveCookieName(t *testing.T) {
	t.Parallel()

	base := config.SessionConfig{CookieName: "passage_session"}
	if got := base.EffectiveCookieName(); got != "passage_session" {
		t.Errorf("insecure: got %q, want %q", got, "passage_session")
	}

	secure := config.SessionConfig{CookieName: "passage_session", CookieSecure: true}
	if got := secure.EffectiveCookieName(); got != "__Host-passage_session" {
		t.Errorf("secure: got %q, want %q", got, "__Host-passage_session")
	}
}

func TestEncryptionKey(t *testing.T) {
	writeConfig := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "passage.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		return path
	}

	hexKey := strings.Repeat("01", 32)

	tests := []struct {
		name string
		yaml string
		env  string // PASSAGE_SECURITY_ENCRYPTION_KEY; empty means unset
		want string
	}{
		{
			name: "default is empty (key file is used)",
			want: "",
		},
		{
			name: "yaml value is loaded",
			yaml: "security:\n  encryption_key: " + hexKey + "\n",
			want: hexKey,
		},
		{
			name: "env overrides the file",
			yaml: "security:\n  encryption_key: " + hexKey + "\n",
			env:  strings.Repeat("02", 32),
			want: strings.Repeat("02", 32),
		},
		{
			name: "env alone is enough",
			env:  hexKey,
			want: hexKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PASSAGE_SECURITY_ENCRYPTION_KEY", tt.env)

			var path string
			if tt.yaml != "" {
				path = writeConfig(t, tt.yaml)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Security.EncryptionKey != tt.want {
				t.Errorf("Security.EncryptionKey = %q; want %q", cfg.Security.EncryptionKey, tt.want)
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate: unexpected error: %v", err)
			}
		})
	}
}
