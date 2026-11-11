package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/settings"
)

func TestSettings_TabsRenderTheirOwnFields(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	tests := []struct {
		tab   string
		wants []string
	}{
		{"general", []string{`name="allow_registration"`, `name="session_duration_hours"`, `name="ui_theme"`}},
		{"signin", []string{`name="login_tagline"`, `name="login_header_phrase"`, `name="login_header_style"`}},
		{"auth", []string{`name="auth_password_enabled"`, `name="auth_max_login_failures"`, `name="auth_bcrypt_cost"`}},
		{"email", []string{`name="smtp_host"`, `name="smtp_port"`, `name="magic_link_ttl_minutes"`}},
		{"limits", []string{`name="rate_limit_login_requests"`, `name="rate_limit_login_window_minutes"`, `name="rate_limit_setup_requests"`}},
		{"security", []string{`name="webhook_url"`, `name="metrics_enabled"`, `name="metrics_token"`}},
	}

	for _, tt := range tests {
		t.Run(tt.tab, func(t *testing.T) {
			body := adminRequest(t, router, http.MethodGet, "/admin/settings?tab="+tt.tab,
				token, f.cfg.Session.CookieName, nil, "").Body.String()
			for _, want := range tt.wants {
				if !strings.Contains(body, want) {
					t.Errorf("tab %q: missing %s", tt.tab, want)
				}
			}
			// The hidden tab field keeps the redirect (and a rejected form) here.
			if !strings.Contains(body, `name="tab" value="`+tt.tab+`"`) {
				t.Errorf("tab %q: missing hidden tab field", tt.tab)
			}
		})
	}
}

// TestSettings_SavesOnlyTheSubmittedTab proves the tabs are independent: a
// general save cannot rewrite the authentication toggles.
func TestSettings_SavesOnlyTheSubmittedTab(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	ctx := context.Background()
	if err := f.settings.Set(ctx, "auth_password_enabled", "false"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	form := url.Values{"tab": {"general"}, "allow_registration": {"on"},
		"session_duration_hours": {"48"}, "session_idle_timeout_minutes": {"0"}, "ui_theme": {"nord"}}
	rec := adminRequest(t, router, http.MethodPost, "/admin/settings", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if rec.Result().StatusCode != http.StatusFound {
		t.Fatalf("status = %d; want 302 (%s)", rec.Result().StatusCode, rec.Body.String())
	}
	if loc := rec.Result().Header.Get("Location"); !strings.Contains(loc, "tab=general") {
		t.Errorf("redirect = %q, want it to return to the general tab", loc)
	}

	want := map[string]string{
		"allow_registration":     "true",
		"session_duration_hours": "48",
		"ui_theme":               "nord",
		// Untouched by this tab:
		"auth_password_enabled": "false",
	}
	for key, wantVal := range want {
		got, err := f.settings.Get(ctx, key)
		if err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		if got != wantVal {
			t.Errorf("%s = %q; want %q", key, got, wantVal)
		}
	}
}

// TestSettings_Validation pins the messages and that a rejected save preserves
// what the operator typed and writes nothing.
func TestSettings_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tab  string
		form url.Values
		want string
		keep string // markup that must survive the re-render
	}{
		{
			name: "session duration out of range",
			tab:  "general",
			form: url.Values{"session_duration_hours": {"0"}, "session_idle_timeout_minutes": {"0"}, "ui_theme": {"slate"}},
			want: "enter a whole number between 1 and 8760",
			keep: `value="0"`,
		},
		{
			name: "theme must be a known option",
			tab:  "general",
			form: url.Values{"session_duration_hours": {"24"}, "session_idle_timeout_minutes": {"0"}, "ui_theme": {"neon"}},
			want: "choose one of the listed options",
		},
		{
			name: "no auth method left",
			tab:  "auth",
			form: url.Values{"auth_max_login_failures": {"5"}, "auth_lockout_minutes": {"15"}, "auth_bcrypt_cost": {"12"}},
			want: "At least one authentication method must stay enabled.",
		},
		{
			name: "magic link without smtp",
			tab:  "auth",
			form: url.Values{"auth_password_enabled": {"on"}, "auth_magic_link_enabled": {"on"},
				"auth_max_login_failures": {"5"}, "auth_lockout_minutes": {"15"}, "auth_bcrypt_cost": {"12"}},
			want: "Magic link needs an SMTP host",
		},
		{
			name: "webhook url must be absolute",
			tab:  "security",
			form: url.Values{"webhook_url": {"not a url"}, "webhook_timeout_seconds": {"5"}, "metrics_enabled": {"on"}},
			want: "use an absolute http or https URL",
		},
		{
			name: "bcrypt cost caps at 14",
			tab:  "auth",
			form: url.Values{"auth_password_enabled": {"on"}, "auth_max_login_failures": {"5"},
				"auth_lockout_minutes": {"15"}, "auth_bcrypt_cost": {"20"}},
			want: "between 10 and 14",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			adminUser := createAdminUser(t, f, "admin", "admin@example.com")
			token := createSession(t, f, adminUser.ID)
			router := buildAdminRouter(f)

			tt.form.Set("tab", tt.tab)
			rec := adminRequest(t, router, http.MethodPost, "/admin/settings", token, f.cfg.Session.CookieName,
				strings.NewReader(tt.form.Encode()), "application/x-www-form-urlencoded")
			if rec.Result().StatusCode != http.StatusOK {
				t.Fatalf("status = %d; want 200 (re-render)", rec.Result().StatusCode)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tt.want) {
				t.Errorf("body missing %q", tt.want)
			}
			if tt.keep != "" && !strings.Contains(body, tt.keep) {
				t.Errorf("body missing preserved value %q", tt.keep)
			}
		})
	}
}

// TestSettings_SignInCopy covers the tagline and header fields through the
// sign-in tab, which is what the login page reads.
func TestSettings_SignInCopy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	form := url.Values{
		"tab":                 {"signin"},
		"login_tagline":       {"Welcome to the lab"},
		"login_header_phrase": {"Packden"},
		"login_header_style":  {"plain"},
	}
	rec := adminRequest(t, router, http.MethodPost, "/admin/settings", token, f.cfg.Session.CookieName,
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if rec.Result().StatusCode != http.StatusFound {
		t.Fatalf("status = %d; want 302 (%s)", rec.Result().StatusCode, rec.Body.String())
	}

	ctx := context.Background()
	for key, want := range map[string]string{
		settings.Tagline:      "Welcome to the lab",
		settings.HeaderPhrase: "Packden",
		settings.HeaderStyle:  "plain",
	} {
		got, err := f.settings.Get(ctx, key)
		if err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		if got != want {
			t.Errorf("%s = %q; want %q", key, got, want)
		}
	}

	body := adminRequest(t, router, http.MethodGet, "/admin/settings?tab=signin",
		token, f.cfg.Session.CookieName, nil, "").Body.String()
	for _, want := range []string{`value="Welcome to the lab"`, `value="Packden"`, `id="login_header_style-plain"`, `checked`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q", want)
		}
	}
}

// TestSettings_SecretsAndLimits covers the password fields and the paired rate
// limit inputs.
func TestSettings_SecretsAndLimits(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	adminUser := createAdminUser(t, f, "admin", "admin@example.com")
	token := createSession(t, f, adminUser.ID)
	router := buildAdminRouter(f)

	sec := url.Values{
		"tab": {"security"}, "webhook_url": {"https://ntfy.example.com/topic"},
		"webhook_secret": {"s3cret"}, "webhook_timeout_seconds": {"5"},
		"metrics_enabled": {"on"}, "metrics_token": {"scrape-me"},
	}
	if rec := adminRequest(t, router, http.MethodPost, "/admin/settings", token, f.cfg.Session.CookieName,
		strings.NewReader(sec.Encode()), "application/x-www-form-urlencoded"); rec.Result().StatusCode != http.StatusFound {
		t.Fatalf("security save: %d", rec.Result().StatusCode)
	}

	lim := url.Values{
		"tab":                       {"limits"},
		"rate_limit_login_requests": {"12"}, "rate_limit_login_window_minutes": {"20"},
		"rate_limit_register_requests": {"0"}, "rate_limit_register_window_minutes": {"60"},
		"rate_limit_reset_requests": {"5"}, "rate_limit_reset_window_minutes": {"60"},
		"rate_limit_magic_link_requests": {"5"}, "rate_limit_magic_link_window_minutes": {"60"},
		"rate_limit_oauth_token_requests": {"20"}, "rate_limit_oauth_token_window_minutes": {"1"},
		"rate_limit_setup_requests": {"5"}, "rate_limit_setup_window_minutes": {"60"},
	}
	if rec := adminRequest(t, router, http.MethodPost, "/admin/settings", token, f.cfg.Session.CookieName,
		strings.NewReader(lim.Encode()), "application/x-www-form-urlencoded"); rec.Result().StatusCode != http.StatusFound {
		t.Fatalf("limits save: %d (%s)", rec.Result().StatusCode, rec.Body.String())
	}

	ctx := context.Background()
	for key, want := range map[string]string{
		settings.WebhookURL:                  "https://ntfy.example.com/topic",
		settings.WebhookSecret:               "s3cret",
		settings.MetricsEnabled:              "true",
		settings.MetricsToken:                "scrape-me",
		settings.RateLimitLoginRequests:      "12",
		settings.RateLimitLoginWindowMinutes: "20",
		settings.RateLimitRegisterRequests:   "0",
	} {
		got, err := f.settings.Get(ctx, key)
		if err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		if got != want {
			t.Errorf("%s = %q; want %q", key, got, want)
		}
	}
}
