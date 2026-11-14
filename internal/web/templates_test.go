package web_test

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/theme"
	"github.com/crueber/passage/internal/web"
)

// themeFunc stands in for the "theme" template function that cmd/passage wires
// to the server default and the page's account override.
func themeFunc(any) string { return theme.Default() }

// TestTemplates_ThemeWiring guards the two things every full page must carry:
// the data-theme hook on <html> and the theme stylesheet in <head>. Adding a new
// page without them fails here rather than shipping an unthemed page. Themes are
// rendered server-side, so no client script is required.
func TestTemplates_ThemeWiring(t *testing.T) {
	t.Parallel()

	var pages int
	err := filepath.Walk("templates", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body := string(src)
		if !strings.Contains(body, "<html") {
			return nil // partial — no document element
		}
		pages++

		checks := []struct {
			name   string
			needle string
		}{
			{"data-theme hook", `<html lang="en" data-theme="{{theme .}}">`},
			{"themes stylesheet", `<link rel="stylesheet" href="/static/themes.css">`},
		}
		for _, c := range checks {
			if !strings.Contains(body, c.needle) {
				t.Errorf("%s: missing %s (%q)", path, c.name, c.needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
	if pages == 0 {
		t.Fatal("no full-page templates found")
	}
}

// TestRender_ThemeAttributes executes the login and admin settings pages with
// the same FuncMap production uses, proving the theme func and the picker data
// are wired end to end (template errors only surface at execution time).
func TestRender_ThemeAttributes(t *testing.T) {
	t.Parallel()

	tmpl, err := web.Parse(web.TemplateFS, template.FuncMap{
		"csrfField": func(_ string) template.HTML { return "" },
		"theme":     themeFunc,
	})
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	login := struct {
		Flash             any
		CSRFToken         string
		Username          string
		RedirectTo        string
		AllowPassword     bool
		AllowPasskey      bool
		AllowMagicLink    bool
		AllowProviders    []struct{ Name, Label string }
		AllowRegistration bool
		Tagline           string
		Wordmark          string
	}{
		AllowPassword: true,
		Tagline:       "Self-hosted authentication for your home lab",
		Wordmark:      "passage",
	}

	type testOption struct{ Value, Label string }
	type testField struct {
		Kind, Key, Key2, Label, Label2, Help, Value, Value2 string
		Min, Max, MaxLen                                    int
		Placeholder                                         string
		Options                                             []testOption
	}
	type testSection struct {
		ID, Title, Sub string
		Fields         []testField
	}
	settings := struct {
		ActiveNav string
		UserName  string
		Flash     any
		CSRFToken string
		Tabs      []struct {
			ID, Title string
			Active    bool
		}
		Active testSection
	}{
		UserName: "Admin User",
		Tabs: []struct {
			ID, Title string
			Active    bool
		}{{ID: "general", Title: "General", Active: true}},
		Active: testSection{
			ID: "general", Title: "General", Sub: "Registration and sessions.",
			Fields: []testField{
				{Kind: "bool", Key: "allow_registration", Label: "Allow public registration", Value: "true"},
				{Kind: "number", Key: "session_duration_hours", Label: "Session duration (hours)", Value: "24", Min: 1, Max: 8760},
				{Kind: "number_pair", Key: "rate_limit_login_requests", Key2: "rate_limit_login_window_minutes", Label: "Sign-in", Label2: "Window (minutes)", Value: "10", Value2: "15", Max: 100000},
				{Kind: "select", Key: "ui_theme", Label: "Server default theme", Value: "cool-slate", Options: []testOption{{Value: "cool-slate", Label: "Cool Slate"}}},
				{Kind: "radio", Key: "login_header_style", Label: "Header style", Value: "for", Options: []testOption{{Value: "for", Label: "Keep the name first"}, {Value: "plain", Label: "Drop it"}}},
				{Kind: "password", Key: "metrics_token", Label: "Metrics bearer token", MaxLen: 200},
			},
		},
	}

	mfa := struct {
		Flash            any
		CSRFToken        string
		Username         string
		PasskeyAvailable bool
		Tagline          string
		Wordmark         string
	}{
		Tagline:  "Self-hosted authentication for your home lab",
		Wordmark: "passage for the Rueber lab",
	}

	tests := []struct {
		template string
		data     any
		needles  []string
	}{
		{
			template: "login.html",
			data:     login,
			needles: []string{
				`data-theme="` + theme.Default() + `"`,
				`/static/themes.css`,
			},
		},
		{
			template: "login_mfa.html",
			data:     mfa,
			needles: []string{
				`data-theme="` + theme.Default() + `"`,
				`/static/themes.css`,
				`<span class="break-words">passage for the Rueber lab</span>`,
				`Self-hosted authentication for your home lab`,
			},
		},
		{
			template: "admin-settings",
			data:     settings,
			needles: []string{
				`data-theme="` + theme.Default() + `"`,
				`/static/themes.css`,
				`<title>General — Passage Admin</title>`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, tt.template, tt.data); err != nil {
				t.Fatalf("execute %s: %v", tt.template, err)
			}
			out := buf.String()
			for _, want := range tt.needles {
				if !strings.Contains(out, want) {
					t.Errorf("%s output missing %q", tt.template, want)
				}
			}
		})
	}
}
