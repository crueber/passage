// Package theme is the static registry of UI colour themes.
//
// It is pure data: no I/O, no environment lookups, and no mutable state. The
// CSS itself lives in internal/web/ui/themes/<name>.css and is compiled into
// internal/web/static/themes.css by tools/build-themes.sh.
//
// A theme's Name must match its CSS file basename, and is the value of the
// data-theme attribute on <html> and of the ui.theme config key.
package theme

// Theme describes one selectable UI colour theme.
type Theme struct {
	// Name is the lowercase slug used in data-theme, config, and the CSS
	// filename (internal/web/ui/themes/<name>.css).
	Name string
	// Label is the human-readable name shown in the appearance picker.
	Label string
	// Description is a one-line summary shown next to the label.
	Description string
}

// All is the registry, in display order. The first entry is the default.
//
// Keep this list in sync with internal/web/ui/themes/: every entry must have a
// CSS file and every CSS file must have an entry (enforced by tests).
var All = []Theme{
	{Name: "slate", Label: "Slate", Description: "Neutral cool gray with a steel-blue primary."},
	{Name: "nord", Label: "Nord", Description: "Arctic blue-gray with frost-blue accents."},
	{Name: "gruvbox", Label: "Gruvbox", Description: "Warm retro earth tones: cream, olive, amber, rust."},
	{Name: "solarized", Label: "Solarized", Description: "Precision teal and sand with a blue primary."},
	{Name: "catppuccin", Label: "Catppuccin", Description: "Soft pastel Latte and Mocha with a mauve primary."},
	{Name: "tokyo-night", Label: "Tokyo Night", Description: "Neon indigo night with periwinkle and cyan."},
	{Name: "rose-pine", Label: "Rosé Pine", Description: "Muted rose and iris over soft dusk surfaces."},
	{Name: "everforest", Label: "Everforest", Description: "Earthy parchment and deep green-gray, sage primary."},
	{Name: "kanagawa", Label: "Kanagawa", Description: "Ink-wash sumi surfaces with wave blue and dragon red."},
	{Name: "paper", Label: "Paper", Description: "Warm editorial off-white with sepia and brick."},
}

// defaultName is the theme used when ui.theme is left at its default.
const defaultName = "slate"

// Default returns the name of the default theme. It is always a member of All.
func Default() string { return defaultName }

// Names returns the registered theme names in registry order.
func Names() []string {
	out := make([]string, len(All))
	for i, t := range All {
		out[i] = t.Name
	}
	return out
}

// Lookup returns the theme with the given name.
func Lookup(name string) (Theme, bool) {
	for _, t := range All {
		if t.Name == name {
			return t, true
		}
	}
	return Theme{}, false
}
