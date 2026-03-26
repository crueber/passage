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
