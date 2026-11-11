package settings_test

import (
	"context"
	"errors"
	"testing"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/settings"
)

// stubStore is an in-memory settings store.
type stubStore struct {
	data map[string]string
	err  error
}

func (s *stubStore) Get(_ context.Context, key string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	v, ok := s.data[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func TestAccessors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	st := &stubStore{data: map[string]string{
		"b":     "true",
		"b_off": " FALSE ",
		"b_bad": "maybe",
		"i":     "42",
		"i_low": "0",
		"i_bad": "lots",
		"s":     "  hello  ",
		"s_emp": "   ",
	}}

	if got := settings.Bool(ctx, st, "b", false); !got {
		t.Error("Bool stored true = false")
	}
	if got := settings.Bool(ctx, st, "b_off", true); got {
		t.Error("Bool stored FALSE = true")
	}
	if got := settings.Bool(ctx, st, "b_bad", true); !got {
		t.Error("Bool malformed did not fall back")
	}
	if got := settings.Bool(ctx, st, "missing", true); !got {
		t.Error("Bool missing did not fall back")
	}

	if got := settings.Int(ctx, st, "i", 0, 1, 100); got != 42 {
		t.Errorf("Int = %d, want 42", got)
	}
	if got := settings.Int(ctx, st, "i_low", 7, 1, 100); got != 7 {
		t.Errorf("Int out of range = %d, want fallback 7", got)
	}
	if got := settings.Int(ctx, st, "i_bad", 9, 0, 100); got != 9 {
		t.Errorf("Int malformed = %d, want fallback 9", got)
	}

	if got := settings.String(ctx, st, "s", "fb"); got != "  hello  " {
		t.Errorf("String = %q, want the stored value", got)
	}
	if got := settings.String(ctx, st, "s_emp", "fb"); got != "fb" {
		t.Errorf("String blank = %q, want the fallback", got)
	}
	if got := settings.Raw(ctx, st, "s_emp", "fb"); got != "   " {
		t.Errorf("Raw blank = %q, want the stored blank", got)
	}
	if got := settings.Raw(ctx, st, "missing", "fb"); got != "fb" {
		t.Errorf("Raw missing = %q, want the fallback", got)
	}

	// A failing store never breaks a request: every accessor falls back.
	broken := &stubStore{err: errors.New("db down")}
	if !settings.Bool(ctx, broken, "b", true) {
		t.Error("Bool with a failing store did not fall back")
	}
	if got := settings.Int(ctx, broken, "i", 3, 0, 10); got != 3 {
		t.Error("Int with a failing store did not fall back")
	}

	// A nil store is the "no settings configured" test fixture.
	if !settings.Bool(ctx, nil, "b", true) {
		t.Error("Bool with a nil store did not fall back")
	}
}

// TestApplyToConfig proves the stored values reach the config snapshot that
// constructors read, and that a nonsense value is ignored instead of breaking
// startup.
func TestApplyToConfig(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	st := &stubStore{data: map[string]string{
		settings.AllowRegistration:           "false",
		settings.BcryptCost:                  "11",
		settings.SessionDurationHours:        "48",
		settings.SessionIdleTimeoutMinutes:   "30",
		settings.MetricsEnabled:              "false",
		settings.MetricsToken:                "tok",
		settings.WebhookURL:                  "https://example.com/hook",
		settings.WebhookTimeoutSeconds:       "9",
		settings.SMTPHost:                    "smtp.example.com",
		settings.SMTPPort:                    "2525",
		settings.Theme:                       "nord",
		settings.RateLimitLoginRequests:      "7",
		settings.RateLimitLoginWindowMinutes: "3",
		settings.MaxLoginFailures:            "not-a-number",
	}}

	cfg := &config.Config{}
	settings.ApplyToConfig(ctx, st, cfg, nil)

	if cfg.Auth.AllowRegistration {
		t.Error("AllowRegistration = true, want false")
	}
	if cfg.Auth.BcryptCost != 11 {
		t.Errorf("BcryptCost = %d, want 11", cfg.Auth.BcryptCost)
	}
	if cfg.Session.DurationHours != 48 {
		t.Errorf("DurationHours = %d, want 48", cfg.Session.DurationHours)
	}
	if cfg.Session.IdleTimeoutMinutes != 30 {
		t.Errorf("IdleTimeoutMinutes = %d, want 30", cfg.Session.IdleTimeoutMinutes)
	}
	if cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled = true, want false")
	}
	if cfg.Metrics.Token != "tok" {
		t.Errorf("Metrics.Token = %q", cfg.Metrics.Token)
	}
	if cfg.Security.WebhookURL != "https://example.com/hook" {
		t.Errorf("WebhookURL = %q", cfg.Security.WebhookURL)
	}
	if cfg.Security.WebhookTimeoutSeconds != 9 {
		t.Errorf("WebhookTimeoutSeconds = %d, want 9", cfg.Security.WebhookTimeoutSeconds)
	}
	if cfg.SMTP.Host != "smtp.example.com" || cfg.SMTP.Port != 2525 {
		t.Errorf("SMTP = %q:%d", cfg.SMTP.Host, cfg.SMTP.Port)
	}
	if cfg.UI.Theme != "nord" {
		t.Errorf("Theme = %q", cfg.UI.Theme)
	}
	if cfg.RateLimit.LoginRequests != 7 || cfg.RateLimit.LoginWindowMinutes != 3 {
		t.Errorf("login limit = %d/%d", cfg.RateLimit.LoginRequests, cfg.RateLimit.LoginWindowMinutes)
	}
	// Malformed input leaves the built-in default in place.
	if cfg.Auth.MaxLoginFailures != 0 {
		t.Errorf("MaxLoginFailures = %d, want the zero default", cfg.Auth.MaxLoginFailures)
	}
}
