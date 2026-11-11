package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/theme"
)

// The settings page is data-driven: each section declares its fields, the
// template renders them uniformly, and the POST handler validates and stores
// one section at a time. Adding a setting is therefore one entry in
// settingsSections plus its reader.
const (
	kindBool       = "bool"
	kindText       = "text"
	kindPassword   = "password"
	kindNumber     = "number"
	kindNumberPair = "number_pair"
	kindSelect     = "select"
	kindRadio      = "radio"
)

type settingsOption struct {
	Value string
	Label string
}

type settingsField struct {
	Kind  string
	Key   string
	Label string
	Help  string
	Value string

	// Number fields.
	Min, Max int
	// KindNumberPair: the second input.
	Key2, Label2 string
	Value2       string
	// Text/password fields.
	MaxLen      int
	Placeholder string
	// Restart marks a setting a constructor reads at startup, so a change
	// applies on the next start.
	Restart bool
	// Options for select/radio.
	Options []settingsOption
}

type settingsSection struct {
	ID     string
	Title  string
	Sub    string
	Fields []settingsField
}

// settingsTabs is the tab order shown on the page.
var settingsTabs = []struct{ ID, Title string }{
	{"general", "General"},
	{"signin", "Sign-in"},
	{"auth", "Authentication"},
	{"email", "Email"},
	{"limits", "Rate limits"},
	{"security", "Security"},
}

// settingsSections builds every section with its current stored values. The
// override map lets a rejected submission re-render what the operator typed.
func (h *Handler) settingsSections(ctx context.Context, override map[string]string) []settingsSection {
	value := func(key string) string {
		if v, ok := override[key]; ok {
			return v
		}
		return settings.Raw(ctx, h.settings, key, settings.Defaults[key])
	}
	boolValue := func(key string) bool {
		if v, ok := override[key]; ok {
			return v == "true"
		}
		return settings.Bool(ctx, h.settings, key, settings.Defaults[key] == "true")
	}

	return []settingsSection{
		{
			ID: "general", Title: "General",
			Sub: "Registration, session lifetime and the default theme.",
			Fields: []settingsField{
				{Kind: kindBool, Key: settings.AllowRegistration, Label: "Allow public registration",
					Help:  "When off, /register explains that an administrator creates accounts.",
					Value: boolString(boolValue(settings.AllowRegistration))},
				{Kind: kindNumber, Key: settings.SessionDurationHours, Label: "Session duration (hours)",
					Help: "Default lifetime for a sign-in. Per-app overrides are set on the app's edit page.",
					Min:  1, Max: 8760, Value: value(settings.SessionDurationHours)},
				{Kind: kindNumber, Key: settings.SessionIdleTimeoutMinutes, Label: "Sign out after inactivity (minutes)",
					Help: "0 keeps the session until its duration runs out, however long the gap.",
					Min:  0, Max: 8760, Value: value(settings.SessionIdleTimeoutMinutes), Restart: true},
				{Kind: kindSelect, Key: settings.Theme, Label: "Server default theme",
					Help:    "The theme every browser starts with. People can still pick their own under Appearance.",
					Value:   value(settings.Theme),
					Options: themeOptions()},
			},
		},
		{
			ID: "signin", Title: "Sign-in page",
			Sub: "What people see before they sign in.",
			Fields: []settingsField{
				{Kind: kindText, Key: settings.Tagline, Label: "Tagline",
					Help:   "The line under the sign-in card. Leave it empty to hide the line.",
					MaxLen: 120, Placeholder: settings.DefaultTagline, Value: value(settings.Tagline)},
				{Kind: kindText, Key: settings.HeaderPhrase, Label: "Header phrase",
					Help:        "Shown in the sign-in header. Empty shows just the Passage name.",
					MaxLen:      60,
					Value:       value(settings.HeaderPhrase),
					Placeholder: "e.g. Packden",
				},
				{Kind: kindRadio, Key: settings.HeaderStyle, Label: "Header style",
					Help:  "With a phrase set, either keep the name first or show the phrase on its own.",
					Value: value(settings.HeaderStyle),
					Options: []settingsOption{
						{Value: "for", Label: "Keep the name first: passage for <phrase>"},
						{Value: "plain", Label: "Drop “passage for”: <phrase>"},
					}},
			},
		},
		{
			ID: "auth", Title: "Authentication methods",
			Sub: "How people can sign in, and the lockout policy.",
			Fields: []settingsField{
				{Kind: kindBool, Key: settings.PasswordEnabled, Label: "Enable password sign-in", Value: boolString(boolValue(settings.PasswordEnabled))},
				{Kind: kindBool, Key: settings.PasskeyEnabled, Label: "Enable passkeys (WebAuthn)", Value: boolString(boolValue(settings.PasskeyEnabled))},
				{Kind: kindBool, Key: settings.MagicLinkEnabled, Label: "Enable magic-link sign-in",
					Help:  magicLinkHelp(settings.String(ctx, h.settings, settings.SMTPHost, h.cfg.SMTP.Host) != ""),
					Value: boolString(boolValue(settings.MagicLinkEnabled))},
				{Kind: kindBool, Key: settings.RequireMFA, Label: "Require two-factor authentication",
					Help:  "Everyone must enrol an authenticator app before using Passage. Passkeys and magic links are not affected.",
					Value: boolString(boolValue(settings.RequireMFA))},
				{Kind: kindNumber, Key: settings.MaxLoginFailures, Label: "Failed sign-ins before a lockout",
					Help: "0 disables per-account throttling.",
					Min:  0, Max: 1000, Value: value(settings.MaxLoginFailures), Restart: true},
				{Kind: kindNumber, Key: settings.LockoutMinutes, Label: "Lockout duration (minutes)",
					Help: "How long a locked account stays locked.",
					Min:  0, Max: 100000, Value: value(settings.LockoutMinutes), Restart: true},
				{Kind: kindNumber, Key: settings.BcryptCost, Label: "Password hashing cost",
					Help: "bcrypt rounds. Higher is slower to verify and to brute-force; 12 is a good default.",
					Min:  10, Max: 14, Value: value(settings.BcryptCost), Restart: true},
			},
		},
		{
			ID: "email", Title: "Email",
			Sub: "SMTP for password resets, address verification and magic links.",
			Fields: []settingsField{
				{Kind: kindText, Key: settings.SMTPHost, Label: "SMTP host",
					Help: "Leave empty to disable outgoing email.", Value: value(settings.SMTPHost), Placeholder: "smtp.example.com", Restart: true},
				{Kind: kindNumber, Key: settings.SMTPPort, Label: "SMTP port",
					Min: 1, Max: 65535, Value: value(settings.SMTPPort), Restart: true},
				{Kind: kindText, Key: settings.SMTPUsername, Label: "SMTP username", Value: value(settings.SMTPUsername), Restart: true},
				{Kind: kindPassword, Key: settings.SMTPPassword, Label: "SMTP password",
					Help: "Stored in the database; leave as-is unless you are changing it.", Value: value(settings.SMTPPassword), Restart: true},
				{Kind: kindSelect, Key: settings.SMTPTLS, Label: "Connection security",
					Value: value(settings.SMTPTLS), Restart: true,
					Options: []settingsOption{
						{Value: "starttls", Label: "STARTTLS (port 587)"},
						{Value: "tls", Label: "Implicit TLS (port 465)"},
						{Value: "none", Label: "None (plaintext)"},
					}},
				{Kind: kindText, Key: settings.SMTPFrom, Label: "From address",
					Help: "The sender; for example Passage <passage@example.com>.", Value: value(settings.SMTPFrom), Placeholder: "Passage <passage@example.com>", Restart: true},
				{Kind: kindNumber, Key: settings.MagicLinkTTLMinutes, Label: "Magic-link lifetime (minutes)",
					Min: 1, Max: 1440, Value: value(settings.MagicLinkTTLMinutes)},
			},
		},
		{
			ID: "limits", Title: "Rate limits",
			Sub: "Per-IP request budgets. 0 requests disables that limit.",
			Fields: []settingsField{
				numberPair(settings.RateLimitLoginRequests, settings.RateLimitLoginWindowMinutes, "Sign-in", value),
				numberPair(settings.RateLimitRegisterRequests, settings.RateLimitRegisterWindowMinutes, "Registration", value),
				numberPair(settings.RateLimitResetRequests, settings.RateLimitResetWindowMinutes, "Password reset", value),
				numberPair(settings.RateLimitMagicLinkRequests, settings.RateLimitMagicLinkWindowMinutes, "Magic link", value),
				numberPair(settings.RateLimitOAuthTokenRequests, settings.RateLimitOAuthTokenWindowMins, "OAuth token endpoint", value),
				numberPair(settings.RateLimitSetupRequests, settings.RateLimitSetupWindowMinutes, "Initial setup", value),
			},
		},
		{
			ID: "security", Title: "Security and monitoring",
			Sub: "Event webhook and the Prometheus endpoint.",
			Fields: []settingsField{
				{Kind: kindText, Key: settings.WebhookURL, Label: "Security webhook URL",
					Help:   "Every authentication event is POSTed here as JSON. Empty disables it.",
					MaxLen: 2048, Value: value(settings.WebhookURL), Placeholder: "https://ntfy.example.com/topic", Restart: true},
				{Kind: kindPassword, Key: settings.WebhookSecret, Label: "Webhook signing secret",
					Help: "Optional. Signs the body with HMAC-SHA256.", Value: value(settings.WebhookSecret), Restart: true},
				{Kind: kindNumber, Key: settings.WebhookTimeoutSeconds, Label: "Webhook timeout (seconds)",
					Min: 1, Max: 60, Value: value(settings.WebhookTimeoutSeconds), Restart: true},
				{Kind: kindBool, Key: settings.MetricsEnabled, Label: "Serve /metrics",
					Help:  "Prometheus metrics at /metrics. Off makes the endpoint answer 404.",
					Value: boolString(boolValue(settings.MetricsEnabled)), Restart: true},
				{Kind: kindPassword, Key: settings.MetricsToken, Label: "Metrics bearer token",
					Help:  "Optional. When set, scrapes must send Authorization: Bearer <token>.",
					Value: value(settings.MetricsToken), Restart: true},
			},
		},
	}
}

// numberPair builds the two inputs of one rate limiter.
func numberPair(reqKey, winKey, label string, value func(string) string) settingsField {
	return settingsField{
		Kind: kindNumberPair,
		Key:  reqKey, Label: label,
		Label2: "Window (minutes)",
		Min:    0, Max: 100000,
		Value:   value(reqKey),
		Value2:  value(winKey),
		Key2:    winKey,
		Restart: true,
	}
}

func magicLinkHelp(smtpConfigured bool) string {
	if smtpConfigured {
		return "Each request sends an email, so it is rate-limited separately."
	}
	return "Set an SMTP host under Email first; saving this switched on without one is refused."
}

func themeOptions() []settingsOption {
	names := theme.Names()
	opts := make([]settingsOption, 0, len(names))
	for _, n := range names {
		t, ok := theme.Lookup(n)
		if ok {
			opts = append(opts, settingsOption{Value: n, Label: t.Label})
			continue
		}
		opts = append(opts, settingsOption{Value: n, Label: n})
	}
	return opts
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// parseSettingsSection validates and returns the submitted values for one
// section. The second return value lists human-readable problems; when it is
// non-empty nothing is written.
func (h *Handler) parseSettingsSection(r *http.Request, sec settingsSection) (map[string]string, []string) {
	values := make(map[string]string, len(sec.Fields))
	var problems []string

	for _, f := range sec.Fields {
		switch f.Kind {
		case kindBool:
			values[f.Key] = boolString(r.FormValue(f.Key) == "on")

		case kindNumberPair:
			for _, k := range []string{f.Key, f.Key2} {
				raw := strings.TrimSpace(r.FormValue(k))
				n, err := strconv.Atoi(raw)
				if err != nil || n < 0 || n > 100000 {
					problems = append(problems, fmt.Sprintf("%s: enter a whole number between 0 and 100000.", fieldLabel(sec, k)))
					continue
				}
				values[k] = strconv.Itoa(n)
			}

		case kindNumber:
			raw := strings.TrimSpace(r.FormValue(f.Key))
			n, err := strconv.Atoi(raw)
			if err != nil || n < f.Min || n > f.Max {
				problems = append(problems, fmt.Sprintf("%s: enter a whole number between %d and %d.", f.Label, f.Min, f.Max))
				continue
			}
			values[f.Key] = strconv.Itoa(n)

		case kindSelect, kindRadio:
			raw := strings.TrimSpace(r.FormValue(f.Key))
			ok := false
			for _, o := range f.Options {
				if o.Value == raw {
					ok = true
					break
				}
			}
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: choose one of the listed options.", f.Label))
				continue
			}
			values[f.Key] = raw

		default: // text, password
			raw := strings.TrimSpace(r.FormValue(f.Key))
			if f.MaxLen > 0 && len(raw) > f.MaxLen {
				problems = append(problems, fmt.Sprintf("%s: at most %d characters.", f.Label, f.MaxLen))
				continue
			}
			if f.Key == settings.WebhookURL && raw != "" {
				u, err := url.Parse(raw)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					problems = append(problems, "Security webhook URL: use an absolute http or https URL.")
					continue
				}
			}
			values[f.Key] = raw
		}
	}

	return values, problems
}

func fieldLabel(sec settingsSection, key string) string {
	for _, f := range sec.Fields {
		if f.Key == key {
			return f.Label
		}
		if f.Kind == kindNumberPair && f.Key2 == key {
			return f.Label + " " + strings.ToLower(f.Label2)
		}
	}
	return key
}
