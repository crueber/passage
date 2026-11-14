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
	// Label is the human-readable name shown in the theme selector.
	Label string
	// Description is a one-line summary shown next to the label.
	Description string
	// LightOnly themes repeat their light palette in the dark block, so they
	// stay light even when the operating system prefers a dark scheme.
	LightOnly bool
}

// All is the registry, in display order. The first entry is the default.
//
// Keep this list in sync with internal/web/ui/themes/: every entry must have a
// CSS file and every CSS file must have an entry (enforced by tests).
var All = []Theme{
	{Name: "cool-slate", Label: "Cool Slate", Description: "Neutral graphite with a steel-blue primary."},
	{Name: "arctic-blue", Label: "Arctic Blue", Description: "Cool blue-gray with frost-blue accents."},
	{Name: "warm-retro", Label: "Warm Retro", Description: "Cream, olive, amber and rust earth tones."},
	{Name: "sand-blue", Label: "Sand & Blue", Description: "Sand canvas with a calibrated blue primary."},
	{Name: "pastel-mauve", Label: "Pastel Mauve", Description: "Soft pastel surfaces with a mauve primary."},
	{Name: "neon-indigo", Label: "Neon Indigo", Description: "Indigo night with periwinkle and cyan."},
	{Name: "dusk-rose", Label: "Dusk Rose", Description: "Muted rose and iris over soft dusk surfaces."},
	{Name: "forest-sage", Label: "Forest Sage", Description: "Parchment and green-gray with sage and olive."},
	{Name: "ink-wash", Label: "Ink Wash", Description: "Sumi ink surfaces with wave blue and dragon red."},
	{Name: "warm-paper", Label: "Warm Paper (Light)", Description: "Warm editorial off-white with sepia and brick. Always light.", LightOnly: true},
	{Name: "clean-white", Label: "Clean White (Light)", Description: "White and gray with a clear blue primary. Always light.", LightOnly: true},
	{Name: "studio-white", Label: "Studio White (Light)", Description: "Soft white, slate text and an indigo primary. Always light.", LightOnly: true},
	{Name: "amber-sand", Label: "Amber Sand (Light)", Description: "Airy warm white with a soft amber primary. Always light.", LightOnly: true},
}

// defaultName is the theme used when ui.theme is left at its default.
const defaultName = "cool-slate"

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

// Lookup returns the theme with the given name. Legacy pre-rename slugs resolve
// to their current theme.
func Lookup(name string) (Theme, bool) {
	name = Canonical(name)
	for _, t := range All {
		if t.Name == name {
			return t, true
		}
	}
	return Theme{}, false
}

// legacyNames maps the pre-rename slugs to their canonical replacements. They
// are accepted forever so a database, bookmark, or config file written before
// the rename still resolves instead of silently falling back to the default.
var legacyNames = map[string]string{
	"slate":        "cool-slate",
	"nord":         "arctic-blue",
	"gruvbox":      "warm-retro",
	"solarized":    "sand-blue",
	"catppuccin":   "pastel-mauve",
	"tokyo-night":  "neon-indigo",
	"rose-pine":    "dusk-rose",
	"everforest":   "forest-sage",
	"kanagawa":     "ink-wash",
	"paper":        "warm-paper",
	"github-light": "clean-white",
	"one-light":    "studio-white",
	"ayu-light":    "amber-sand",
}

// Canonical resolves a legacy slug to its current name and leaves an current or
// unknown value untouched. Use it wherever a stored value is rendered.
func Canonical(name string) string {
	if current, ok := legacyNames[name]; ok {
		return current
	}
	return name
}
