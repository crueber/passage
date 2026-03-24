package web

import (
	"embed"
	"fmt"
	"html/template"
)

//go:embed templates
var TemplateFS embed.FS

// Parse parses all HTML templates from the given filesystem and returns a
// combined *template.Template. The caller is responsible for providing the
// correct embed.FS (typically web.TemplateFS).
//
// All templates are parsed into a single template set so that user-facing pages
// and admin pages share the same namespace (required by html/template).
func Parse(fs embed.FS) (*template.Template, error) {
	tmpl, err := template.ParseFS(fs,
		"templates/*.html",
		"templates/admin/*.html",
	)
	if err != nil {
		return nil, fmt.Errorf("web: parse templates: %w", err)
	}
	return tmpl, nil
}
