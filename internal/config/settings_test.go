package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/crueber/passage/internal/config"
)

// writeTempConfig writes a YAML file for Load.
func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passage.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_ExplicitSettings pins the marker that lets a YAML value override the
// matching admin setting. Only a key that is actually present counts: a
// defaulted value must stay overridable in the UI.
func TestLoad_ExplicitSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		yaml             string
		wantRegistration bool
		wantRequireMFA   bool
		wantDuration     bool
	}{
		{
			name: "absent keys are not explicit",
			yaml: "server:\n  port: 8080\n",
		},
		{
			name:             "false is explicit",
			yaml:             "auth:\n  allow_registration: false\n",
			wantRegistration: true,
		},
		{
			name:             "true is explicit",
			yaml:             "auth:\n  allow_registration: true\n",
			wantRegistration: true,
		},
		{
			name:           "require_mfa is explicit",
			yaml:           "auth:\n  require_mfa: true\n",
			wantRequireMFA: true,
		},
		{
			name:         "duration is explicit",
			yaml:         "session:\n  duration_hours: 8\n",
			wantDuration: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Load(writeTempConfig(t, tt.yaml))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Auth.AllowRegistrationSet != tt.wantRegistration {
				t.Errorf("AllowRegistrationSet = %v, want %v", cfg.Auth.AllowRegistrationSet, tt.wantRegistration)
			}
			if cfg.Auth.RequireMFASet != tt.wantRequireMFA {
				t.Errorf("RequireMFASet = %v, want %v", cfg.Auth.RequireMFASet, tt.wantRequireMFA)
			}
			if cfg.Session.DurationHoursSet != tt.wantDuration {
				t.Errorf("DurationHoursSet = %v, want %v", cfg.Session.DurationHoursSet, tt.wantDuration)
			}
		})
	}
}

// TestLoad_EnvCountsAsExplicit proves an environment override takes the same
// precedence as a YAML key, since both are "the operator configured it".
func TestLoad_EnvCountsAsExplicit(t *testing.T) {
	// Not parallel: it sets process-wide environment variables.
	t.Setenv("PASSAGE_AUTH_ALLOW_REGISTRATION", "false")
	t.Setenv("PASSAGE_AUTH_REQUIRE_MFA", "true")
	t.Setenv("PASSAGE_SESSION_DURATION_HOURS", "6")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Auth.AllowRegistrationSet || cfg.Auth.AllowRegistration {
		t.Errorf("allow_registration env override: set=%v value=%v, want set=false", cfg.Auth.AllowRegistrationSet, cfg.Auth.AllowRegistration)
	}
	if !cfg.Auth.RequireMFASet || !cfg.Auth.RequireMFA {
		t.Errorf("require_mfa env override: set=%v value=%v, want set=true", cfg.Auth.RequireMFASet, cfg.Auth.RequireMFA)
	}
	if !cfg.Session.DurationHoursSet || cfg.Session.DurationHours != 6 {
		t.Errorf("duration env override: set=%v value=%d, want 6", cfg.Session.DurationHoursSet, cfg.Session.DurationHours)
	}
}

// TestBoolSetting pins the precedence rule itself: explicit config, then the
// stored value, then the config default.
func TestBoolSetting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		explicit  bool
		configVal bool
		stored    string
		hasStored bool
		want      bool
	}{
		{name: "explicit true beats stored false", explicit: true, configVal: true, stored: "false", hasStored: true, want: true},
		{name: "explicit false beats stored true", explicit: true, configVal: false, stored: "true", hasStored: true, want: false},
		{name: "stored wins without an explicit value", configVal: true, stored: "false", hasStored: true, want: false},
		{name: "default without config or store", configVal: true, want: true},
		{name: "stored value is trimmed and case-insensitive", stored: " TRUE ", hasStored: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := config.BoolSetting(tt.explicit, tt.configVal, tt.stored, tt.hasStored)
			if got != tt.want {
				t.Errorf("BoolSetting = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIntSetting pins the same rule for the session duration, including the
// rejection of a stored value that is not a positive integer.
func TestIntSetting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		explicit  bool
		configVal int
		stored    string
		hasStored bool
		want      int
	}{
		{name: "explicit beats stored", explicit: true, configVal: 8, stored: "48", hasStored: true, want: 8},
		{name: "stored wins without an explicit value", configVal: 24, stored: "48", hasStored: true, want: 48},
		{name: "default without config or store", configVal: 24, want: 24},
		{name: "garbage stored value falls back", configVal: 24, stored: "soon", hasStored: true, want: 24},
		{name: "zero stored value falls back", configVal: 24, stored: "0", hasStored: true, want: 24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := config.IntSetting(tt.explicit, tt.configVal, tt.stored, tt.hasStored)
			if got != tt.want {
				t.Errorf("IntSetting = %d, want %d", got, tt.want)
			}
		})
	}
}
