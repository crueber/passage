package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/crueber/passage/internal/theme"
)

//go:embed templates
var TemplateFS embed.FS

// Themed is embedded in page data that knows the viewer's theme. The "theme"
// template function reads it via PageTheme; an empty Theme means "follow the
// server default", which the function supplies.
type Themed struct{ Theme string }

// NewThemed builds the theme carrier for a stored slug, resolving a legacy
// pre-rename value to its current name.
func NewThemed(name string) Themed { return Themed{Theme: theme.Canonical(name)} }

// PageTheme returns the embedded theme slug. It exists so the template function
// can resolve a page theme without reflection, and so public pages that do not
// embed Themed simply fall back to the server default.
func (t Themed) PageTheme() string { return t.Theme }

// ThemeFromData returns the theme override carried by template data, or "" when
// the data does not embed Themed. Template functions cannot see the request, so
// the signed-in user's preference is threaded through the render data instead.
func ThemeFromData(data any) string {
	if t, ok := data.(interface{ PageTheme() string }); ok {
		return t.PageTheme()
	}
	return ""
}

// Parse parses all HTML templates from the given filesystem and returns a
// combined *template.Template. The caller is responsible for providing the
// correct embed.FS (typically web.TemplateFS) and a FuncMap containing any
// template helper functions (e.g. "csrfField").
//
// All templates are parsed into a single template set so that user-facing pages
// and admin pages share the same namespace (required by html/template).
func Parse(fs embed.FS, funcs template.FuncMap) (*template.Template, error) {
	tmpl := template.New("").Funcs(funcs)
	tmpl, err := tmpl.ParseFS(fs,
		"templates/*.html",
		"templates/admin/*.html",
	)
	if err != nil {
		return nil, fmt.Errorf("web: parse templates: %w", err)
	}
	return tmpl, nil
}

// Render executes a named template into a buffer before writing HTTP 200 OK so
// a template execution error never flushes a half-written response.
func Render(w http.ResponseWriter, tmpl *template.Template, logger *slog.Logger, name string, data any) {
	RenderStatus(w, tmpl, logger, http.StatusOK, name, data)
}

// RenderStatus executes a named template into a buffer, sets Content-Type,
// writes status, and flushes the rendered HTML.
func RenderStatus(w http.ResponseWriter, tmpl *template.Template, logger *slog.Logger, status int, name string, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		if logger != nil {
			logger.Error("render template", "template", name, "error", err)
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}
