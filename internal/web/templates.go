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
func Parse(fs embed.FS) (*template.Template, error) {
	tmpl, err := template.ParseFS(fs,
		"templates/*.html",
	)
	if err != nil {
		return nil, fmt.Errorf("web: parse templates: %w", err)
	}
	return tmpl, nil
}
