package session

import "strings"

// maxUserAgentScan bounds how much of a User-Agent header is inspected. Real
// headers are a few hundred bytes; anything longer is either a bot or an
// attempt to make us burn CPU, and the labels we produce do not depend on it.
const maxUserAgentScan = 512

// userAgentBrowser matches a lowercase token in the User-Agent string to a
// browser label. Order matters: Chromium-derived browsers also advertise
// "Chrome", and Chrome advertises "Safari".
var userAgentBrowser = []struct {
	token string
	label string
}{
	{"edg/", "Edge"},
	{"edga/", "Edge"},
	{"opr/", "Opera"},
	{"fxios/", "Firefox"},
	{"crios/", "Chrome"},
	{"firefox/", "Firefox"},
	{"chrome/", "Chrome"},
	{"safari/", "Safari"},
	{"curl/", "curl"},
	{"wget/", "wget"},
	{"python-requests/", "Python requests"},
	{"go-http-client/", "Go HTTP client"},
}

// userAgentPlatform matches a lowercase token to a platform label. Order
// matters: Android and iOS strings also contain "Linux" and "Mac OS X".
var userAgentPlatform = []struct {
	token string
	label string
}{
	{"windows", "Windows"},
	{"android", "Android"},
	{"iphone", "iOS"},
	{"ipad", "iOS"},
	{"cros", "ChromeOS"},
	{"mac os x", "macOS"},
	{"macintosh", "macOS"},
	{"linux", "Linux"},
}

// DeviceSummary returns a short human-readable device summary derived from a
// User-Agent string, e.g. "Firefox on Linux" or "Safari on iOS", for display in
// the sessions list.
//
// It is a display heuristic, not a parser: it recognises the handful of
// browsers and platforms a self-hosted deployment realistically sees and falls
// back to a generic label. It is safe for hostile input — it only scans a
// bounded prefix and returns a constant string when nothing matches, so it
// never panics, never echoes raw input, and never returns HTML.
func DeviceSummary(ua string) string {
	if len(ua) > maxUserAgentScan {
		ua = ua[:maxUserAgentScan]
	}
	lower := strings.ToLower(ua)

	var browser string
	for _, rule := range userAgentBrowser {
		if strings.Contains(lower, rule.token) {
			browser = rule.label
			break
		}
	}

	var platform string
	for _, rule := range userAgentPlatform {
		if strings.Contains(lower, rule.token) {
			platform = rule.label
			break
		}
	}

	switch {
	case browser == "" && platform == "":
		return "Unknown device"
	case platform == "":
		return browser
	case browser == "":
		return "Unknown browser on " + platform
	default:
		return browser + " on " + platform
	}
}
