package session

import (
	"strings"
	"testing"
)

func TestDeviceSummary(t *testing.T) {
	t.Parallel()

	const (
		firefoxLinux   = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
		chromeWindows  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
		safariMac      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
		safariIPhone   = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
		chromeAndroid  = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
		edgeWindows    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
		operaLinux     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0"
		chromeos       = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
		chromeIOS      = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.0.0 Mobile/15E148 Safari/604.1"
		curl           = "curl/8.7.1"
		firefoxNoPlatf = "Mozilla/5.0 Firefox/128.0"
		linuxNoBrowser = "Mozilla/5.0 (X11; Linux x86_64)"
	)

	cases := []struct {
		name string
		ua   string
		want string
	}{
		{name: "firefox on linux", ua: firefoxLinux, want: "Firefox on Linux"},
		{name: "chrome on windows", ua: chromeWindows, want: "Chrome on Windows"},
		{name: "safari on macos", ua: safariMac, want: "Safari on macOS"},
		{name: "safari on ios", ua: safariIPhone, want: "Safari on iOS"},
		{name: "chrome on android", ua: chromeAndroid, want: "Chrome on Android"},
		{name: "edge is not chrome", ua: edgeWindows, want: "Edge on Windows"},
		{name: "opera is not chrome", ua: operaLinux, want: "Opera on Linux"},
		{name: "chromeos", ua: chromeos, want: "Chrome on ChromeOS"},
		{name: "chrome on ios", ua: chromeIOS, want: "Chrome on iOS"},
		{name: "command line client", ua: curl, want: "curl"},
		{name: "browser without platform", ua: firefoxNoPlatf, want: "Firefox"},
		{name: "platform without browser", ua: linuxNoBrowser, want: "Unknown browser on Linux"},
		{name: "empty", ua: "", want: "Unknown device"},
		{name: "whitespace", ua: "   ", want: "Unknown device"},
		{name: "garbage", ua: "!!! not a user agent ???", want: "Unknown device"},
		{name: "binary garbage", ua: "\x00\x01\x02\xff\xfe garbage", want: "Unknown device"},
		{name: "newlines only", ua: "\n\r\t", want: "Unknown device"},
		{name: "very long unmatched header", ua: strings.Repeat("A", 100_000), want: "Unknown device"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := DeviceSummary(tc.ua); got != tc.want {
				t.Errorf("DeviceSummary(%q) = %q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

// TestDeviceSummary_NeverPanicsOrEchoes verifies hostile input cannot panic the
// helper or leak the raw string into the summary. It runs every byte value and
// a set of pathological shapes.
func TestDeviceSummary_NeverPanicsOrEchoes(t *testing.T) {
	t.Parallel()

	var all strings.Builder
	for i := 0; i < 256; i++ {
		all.WriteByte(byte(i))
	}
	inputs := []string{
		all.String(),
		strings.Repeat("<script>alert(1)</script>", 100),
		strings.Repeat("chrome/ ", 1000),
		"%s%n%d",
	}

	for _, in := range inputs {
		got := DeviceSummary(in)
		if got == "" {
			t.Errorf("DeviceSummary(%q) returned an empty summary", in[:min(len(in), 32)])
		}
		if strings.Contains(got, "script") || strings.Contains(got, "%s") {
			t.Errorf("DeviceSummary echoed input: %q", got)
		}
	}
}
