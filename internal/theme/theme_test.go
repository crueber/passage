package theme_test

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/theme"
)

// themesDir is the source directory for theme CSS, relative to this package.
const themesDir = "../web/ui/themes"

// staticThemesCSS is the generated bundle committed under internal/web/static.
const staticThemesCSS = "../web/static/themes.css"

// colorTokens is the complete set of custom properties every theme block must
// define. Keep in sync with docs/theming.md.
var colorTokens = []string{
	// brand ramp
	"brand-50", "brand-100", "brand-200", "brand-300", "brand-400", "brand-500",
	"brand-600", "brand-700", "brand-800", "brand-900", "brand-950",
	// surfaces + text
	"canvas", "surface", "raised", "line", "ink", "muted", "faint",
	// primary actions
	"primary", "primary-hover", "on-primary",
	"primary-soft", "primary-soft-hover", "on-primary-soft",
	// status
	"success", "success-soft", "on-success-soft",
	"danger", "danger-hover", "danger-soft", "on-danger-soft",
	"warn", "warn-soft", "on-warn-soft",
	// accent
	"glow",
}

// shadowTokens are the only non-hex tokens; shadows carry rgb() colour stops.
var shadowTokens = []string{"card", "pop"}

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// contrastPair is one WCAG AA requirement measured against parsed hex values.
type contrastPair struct {
	fg, bg string
	min    float64
}

var contrastPairs = []contrastPair{
	{"ink", "canvas", 4.5},
	{"ink", "surface", 4.5},
	{"muted", "surface", 4.5},
	{"faint", "surface", 3.0},
	{"primary", "surface", 4.5},
	{"on-primary", "primary", 4.5},
	{"on-primary-soft", "primary-soft", 4.5},
	{"on-success-soft", "success-soft", 4.5},
	{"on-danger-soft", "danger-soft", 4.5},
	{"on-warn-soft", "warn-soft", 4.5},
}

// themeBlock is one parsed :root[data-theme="x"] rule.
type themeBlock struct {
	// colors maps token name (without the --color- prefix) to its hex value.
	colors map[string]string
	// shadows maps token name (without the --shadow- prefix) to raw value.
	shadows map[string]string
}

func TestRegistry(t *testing.T) {
	t.Parallel()

	if len(theme.All) == 0 {
		t.Fatal("registry is empty")
	}

	seen := make(map[string]bool, len(theme.All))
	for _, th := range theme.All {
		if !slugPattern.MatchString(th.Name) {
			t.Errorf("theme %q: name is not a valid slug (want ^[a-z][a-z0-9-]*$)", th.Name)
		}
		if seen[th.Name] {
			t.Errorf("theme %q: duplicate name in registry", th.Name)
		}
		seen[th.Name] = true
		if strings.TrimSpace(th.Label) == "" {
			t.Errorf("theme %q: empty label", th.Name)
		}
		if strings.TrimSpace(th.Description) == "" {
			t.Errorf("theme %q: empty description", th.Name)
		}
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"len(All)", len(theme.All), 13},
		{"first theme", theme.All[0].Name, "cool-slate"},
		{"Default()", theme.Default(), "cool-slate"},
		{"len(Names())", len(theme.Names()), len(theme.All)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if fmt.Sprint(tt.got) != fmt.Sprint(tt.want) {
				t.Errorf("got %v; want %v", tt.got, tt.want)
			}
		})
	}

	if _, ok := theme.Lookup(theme.Default()); !ok {
		t.Errorf("Default() = %q is not present in the registry", theme.Default())
	}
	if _, ok := theme.Lookup("no-such-theme"); ok {
		t.Error("Lookup(\"no-such-theme\") unexpectedly succeeded")
	}
	// Legacy pre-rename slugs stay resolvable, so an un-migrated row or an old
	// bookmark renders the current theme instead of the default.
	for legacy, current := range map[string]string{
		"slate": "cool-slate", "nord": "arctic-blue", "gruvbox": "warm-retro",
		"solarized": "sand-blue", "catppuccin": "pastel-mauve", "tokyo-night": "neon-indigo",
		"rose-pine": "dusk-rose", "everforest": "forest-sage", "kanagawa": "ink-wash",
		"paper": "warm-paper", "github-light": "clean-white", "one-light": "studio-white",
		"ayu-light": "amber-sand",
	} {
		got, ok := theme.Lookup(legacy)
		if !ok || got.Name != current {
			t.Errorf("Lookup(%q) = %q, %v; want %q", legacy, got.Name, ok, current)
		}
		if got := theme.Canonical(legacy); got != current {
			t.Errorf("Canonical(%q) = %q, want %q", legacy, got, current)
		}
	}

	for i, name := range theme.Names() {
		if name != theme.All[i].Name {
			t.Errorf("Names()[%d] = %q; want %q (registry order)", i, name, theme.All[i].Name)
		}
	}
}

func TestThemeFiles_MatchRegistry(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(themesDir)
	if err != nil {
		t.Fatalf("read %s: %v", themesDir, err)
	}

	onDisk := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".css") {
			continue
		}
		onDisk[strings.TrimSuffix(e.Name(), ".css")] = true
	}

	for _, th := range theme.All {
		if !onDisk[th.Name] {
			t.Errorf("theme %q: missing file %s/%s.css", th.Name, themesDir, th.Name)
		}
	}
	for name := range onDisk {
		if _, ok := theme.Lookup(name); !ok {
			t.Errorf("orphan theme file %s/%s.css: not registered in internal/theme", themesDir, name)
		}
	}
}

func TestThemeFiles_TokenContract(t *testing.T) {
	t.Parallel()

	for _, th := range theme.All {
		t.Run(th.Name, func(t *testing.T) {
			t.Parallel()
			blocks := parseThemeFile(t, th.Name)
			for _, mode := range []string{"light", "dark"} {
				block := blocks[mode]
				for _, tok := range colorTokens {
					val, ok := block.colors[tok]
					if !ok {
						t.Errorf("%s block: missing --color-%s", mode, tok)
						continue
					}
					if !regexp.MustCompile(`^#[0-9a-fA-F]{6}$`).MatchString(val) {
						t.Errorf("%s block: --color-%s = %q; want a 6-digit hex literal", mode, tok, val)
					}
				}
				for _, tok := range shadowTokens {
					if _, ok := block.shadows[tok]; !ok {
						t.Errorf("%s block: missing --shadow-%s", mode, tok)
					}
				}
			}
		})
	}
}

func TestThemeFiles_Contrast(t *testing.T) {
	t.Parallel()

	for _, th := range theme.All {
		t.Run(th.Name, func(t *testing.T) {
			t.Parallel()
			blocks := parseThemeFile(t, th.Name)
			for _, mode := range []string{"light", "dark"} {
				block := blocks[mode]
				for _, p := range contrastPairs {
					fg, fgOK := block.colors[p.fg]
					bg, bgOK := block.colors[p.bg]
					if !fgOK || !bgOK {
						// Missing tokens are reported by the token-contract test.
						continue
					}
					ratio := contrastRatio(t, fg, bg)
					if ratio+1e-9 < p.min {
						t.Errorf("%s block: %s (%s) on %s (%s) = %.2f:1; want >= %.1f:1",
							mode, p.fg, fg, p.bg, bg, ratio, p.min)
					}
				}
			}
		})
	}
}

// TestThemeFiles_LightOnly pins the promise of a light-only theme: its dark
// block must repeat the light palette exactly, so the OS dark preference cannot
// invert it.
func TestThemeFiles_LightOnly(t *testing.T) {
	t.Parallel()

	for _, th := range theme.All {
		if !th.LightOnly {
			continue
		}
		t.Run(th.Name, func(t *testing.T) {
			t.Parallel()
			blocks := parseThemeFile(t, th.Name)
			light, dark := blocks["light"], blocks["dark"]
			for tok, want := range light.colors {
				if got := dark.colors[tok]; got != want {
					t.Errorf("dark --color-%s = %s; want the light value %s", tok, got, want)
				}
			}
			for tok, want := range light.shadows {
				if got := dark.shadows[tok]; got != want {
					t.Errorf("dark --shadow-%s = %s; want the light value %s", tok, got, want)
				}
			}
		})
	}
}

// TestThemeFiles_BrandRamp pins the two load-bearing semantics of the brand
// ramp: brand-950 is the mobile drawer scrim (bg-brand-950/40), so it must be
// darker than the canvas or the drawer washes the page lighter instead of
// dimming it; and the ramp must descend monotonically (50 lightest, 950
// darkest). Themes that invert the ramp for "dark mode" fail here.
func TestThemeFiles_BrandRamp(t *testing.T) {
	t.Parallel()

	steps := []string{"brand-50", "brand-100", "brand-200", "brand-300", "brand-400",
		"brand-500", "brand-600", "brand-700", "brand-800", "brand-900", "brand-950"}

	for _, th := range theme.All {
		t.Run(th.Name, func(t *testing.T) {
			t.Parallel()
			blocks := parseThemeFile(t, th.Name)
			for _, mode := range []string{"light", "dark"} {
				block := blocks[mode]
				previous := math.Inf(1)
				for _, token := range steps {
					hex, ok := block.colors[token]
					if !ok {
						// Missing tokens are reported by the token-contract test.
						continue
					}
					lum := relativeLuminance(t, hex)
					if lum >= previous {
						t.Errorf("%s block: %s (%s) luminance %.4f is not darker than the previous step (%.4f); ramp must descend 50 -> 950",
							mode, token, hex, lum, previous)
					}
					previous = lum
				}
				canvas, ok := block.colors["canvas"]
				scrim, ok2 := block.colors["brand-950"]
				if !ok || !ok2 {
					continue
				}
				if relativeLuminance(t, scrim) >= relativeLuminance(t, canvas) {
					t.Errorf("%s block: brand-950 (%s) is not darker than canvas (%s); the drawer scrim would brighten the page",
						mode, scrim, canvas)
				}
			}
		})
	}
}

// TestStaticThemesCSS_UpToDate pins the committed bundle to a fresh build. It
// mirrors tools/build-themes.sh exactly: header line, blank line, then each
// theme file in sorted filename order followed by a blank line.
func TestStaticThemesCSS_UpToDate(t *testing.T) {
	t.Parallel()

	generated, err := os.ReadFile(staticThemesCSS)
	if err != nil {
		t.Fatalf("read %s: %v (run ./tools/build-themes.sh)", staticThemesCSS, err)
	}

	entries, err := os.ReadDir(themesDir)
	if err != nil {
		t.Fatalf("read %s: %v", themesDir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".css") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	var want strings.Builder
	want.WriteString("/* generated by tools/build-themes.sh — do not edit */\n\n")
	for _, name := range files {
		body, err := os.ReadFile(filepath.Join(themesDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		want.Write(body)
		want.WriteString("\n")
	}

	if got, expect := string(generated), want.String(); got != expect {
		t.Errorf("%s is out of date: run ./tools/build-themes.sh (got %d bytes, want %d)",
			staticThemesCSS, len(got), len(expect))
	}

	// Belt and braces: the bundle must mention every registered theme.
	for _, th := range theme.All {
		if !strings.Contains(string(generated), `:root[data-theme="`+th.Name+`"]`) {
			t.Errorf("%s: missing selector for theme %q", staticThemesCSS, th.Name)
		}
	}
}

// parseThemeFile parses one theme file into its light and dark token blocks.
func parseThemeFile(t *testing.T, name string) map[string]themeBlock {
	t.Helper()

	path := filepath.Join(themesDir, name+".css")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(src)

	selector := `:root[data-theme="` + name + `"]`

	const mediaMarker = "@media (prefers-color-scheme: dark)"
	mediaStart := strings.Index(text, mediaMarker)
	if mediaStart < 0 {
		t.Fatalf("%s: missing %q block", path, mediaMarker)
	}
	mediaBody, _, ok := extractRule(text, mediaStart)
	if !ok {
		t.Fatalf("%s: malformed %q block", path, mediaMarker)
	}

	lightBody, _, ok := extractRule(text[:mediaStart], strings.Index(text[:mediaStart], selector))
	if !ok {
		t.Fatalf("%s: missing light block %s", path, selector)
	}
	darkBody, _, ok := extractRule(mediaBody, strings.Index(mediaBody, selector))
	if !ok {
		t.Fatalf("%s: missing dark block %s inside %q", path, selector, mediaMarker)
	}

	return map[string]themeBlock{
		"light": parseTokens(t, path, lightBody),
		"dark":  parseTokens(t, path, darkBody),
	}
}

// extractRule returns the body of the rule that starts at (or after) the given
// selector offset within src, plus the offset just past its closing brace.
func extractRule(src string, selectorAt int) (string, int, bool) {
	if selectorAt < 0 || selectorAt >= len(src) {
		return "", 0, false
	}
	open := strings.IndexByte(src[selectorAt:], '{')
	if open < 0 {
		return "", 0, false
	}
	open += selectorAt

	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : i], i + 1, true
			}
		}
	}
	return "", 0, false
}

var tokenPattern = regexp.MustCompile(`--(color|shadow)-([a-z0-9-]+)\s*:\s*([^;]+);`)

func parseTokens(t *testing.T, path, body string) themeBlock {
	t.Helper()
	block := themeBlock{colors: map[string]string{}, shadows: map[string]string{}}
	for _, m := range tokenPattern.FindAllStringSubmatch(body, -1) {
		switch m[1] {
		case "color":
			block.colors[m[2]] = strings.TrimSpace(m[3])
		case "shadow":
			block.shadows[m[2]] = strings.TrimSpace(m[3])
		}
	}
	return block
}

// contrastRatio computes the WCAG 2.x contrast ratio between two hex colours.
func contrastRatio(t *testing.T, fg, bg string) float64 {
	t.Helper()
	l1, l2 := relativeLuminance(t, fg), relativeLuminance(t, bg)
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

func relativeLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	h := strings.TrimPrefix(hex, "#")
	if len(h) != 6 {
		t.Fatalf("invalid hex colour %q", hex)
	}
	var ch [3]float64
	for i := range ch {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			t.Fatalf("invalid hex colour %q: %v", hex, err)
		}
		s := float64(v) / 255
		if s <= 0.03928 {
			ch[i] = s / 12.92
		} else {
			ch[i] = math.Pow((s+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*ch[0] + 0.7152*ch[1] + 0.0722*ch[2]
}
