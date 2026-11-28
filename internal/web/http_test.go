package web_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/web"
)

func TestSafeReturnPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rd   string
		want bool
	}{
		{"root", "/", true},
		{"simple path", "/protected/page", true},
		{"path with query", "/oauth/authorize?client_id=abc&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb", true},
		{"empty", "", false},
		{"absolute http", "http://evil.com", false},
		{"absolute https", "https://evil.com/phish", false},
		{"scheme relative", "//evil.com", false},
		{"backslash trick", `/\evil.com`, false},
		{"tab smuggling", "/\t/evil.com", false},
		{"cr smuggling", "/\r/evil.com", false},
		{"lf smuggling", "/\n/evil.com", false},
		{"nul byte", "/foo\x00bar", false},
		{"del byte", "/foo\x7fbar", false},
		{"relative without leading slash", "evil.com", false},
		{"javascript scheme", "javascript:alert(1)", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := web.SafeReturnPath(tc.rd); got != tc.want {
				t.Errorf("SafeReturnPath(%q) = %v, want %v", tc.rd, got, tc.want)
			}
		})
	}
}

func TestReturnCookie_RoundTrip(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/protected/page",
		"/oauth/authorize?client_id=abc&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
		`/search?q=a,b;c "quoted" space`,
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			web.SetReturnCookie(rec, p, false)
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("expected 1 cookie, got %d", len(cookies))
			}

			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			req.AddCookie(cookies[0])
			got, ok := web.ReadReturnCookie(req)
			if !ok || got != p {
				t.Errorf("ReadReturnCookie = (%q, %v), want (%q, true)", got, ok, p)
			}
		})
	}
}

func TestTrustedRealIP(t *testing.T) {
	t.Parallel()

	defaults, err := web.ParseTrustedProxies(config.DefaultTrustedProxies())
	if err != nil {
		t.Fatalf("ParseTrustedProxies(defaults): %v", err)
	}

	tests := []struct {
		name       string
		trusted    []string // nil => defaults; empty slice => trust none
		remoteAddr string
		headers    map[string]string
		wantIP     string
	}{
		{
			name:       "untrusted public peer ignores all forwarding headers",
			remoteAddr: "198.51.100.7:1234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.10",
				"X-Real-IP":       "203.0.113.11",
				"True-Client-IP":  "203.0.113.12",
			},
			wantIP: "198.51.100.7",
		},
		{
			name:       "XFF wins over client-forged X-Real-IP behind Caddy/nginx",
			remoteAddr: "127.0.0.1:4444",
			headers: map[string]string{
				"X-Real-IP":       "1.2.3.4",
				"X-Forwarded-For": "5.6.7.8, 203.0.113.42",
			},
			wantIP: "203.0.113.42",
		},
		{
			name:       "XFF skips trailing trusted proxy hops right-to-left",
			remoteAddr: "10.0.0.5:4444",
			headers: map[string]string{
				"X-Forwarded-For": "9.9.9.9, 203.0.113.50, 172.17.0.1, 100.64.0.2",
			},
			wantIP: "203.0.113.50",
		},
		{
			name:       "CGNAT / Tailscale proxy peer is trusted by default",
			remoteAddr: "100.100.10.2:4444",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.77",
			},
			wantIP: "203.0.113.77",
		},
		{
			name:       "X-Real-IP used as fallback when XFF absent",
			remoteAddr: "127.0.0.1:4444",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.55",
			},
			wantIP: "203.0.113.55",
		},
		{
			name:       "empty trusted list trusts no proxies (direct Docker exposure)",
			trusted:    []string{},
			remoteAddr: "172.17.0.1:4444",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.99",
				"X-Real-IP":       "203.0.113.98",
			},
			wantIP: "172.17.0.1",
		},
		{
			name:       "explicit public LB peer in trusted_proxies is honored",
			trusted:    []string{"198.51.100.10/32"},
			remoteAddr: "198.51.100.10:4444",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.88",
			},
			wantIP: "203.0.113.88",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prefixes := defaults
			if tc.trusted != nil {
				var perr error
				prefixes, perr = web.ParseTrustedProxies(tc.trusted)
				if perr != nil {
					t.Fatalf("ParseTrustedProxies: %v", perr)
				}
			}

			var gotIP string
			var leftoverXFF, leftoverXRI, leftoverTCI string
			h := web.TrustedRealIP(prefixes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotIP = web.ClientIP(r)
				leftoverXFF = r.Header.Get("X-Forwarded-For")
				leftoverXRI = r.Header.Get("X-Real-IP")
				leftoverTCI = r.Header.Get("True-Client-IP")
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)

			if gotIP != tc.wantIP {
				t.Errorf("ClientIP = %q, want %q", gotIP, tc.wantIP)
			}
			if leftoverXFF != "" || leftoverXRI != "" || leftoverTCI != "" {
				t.Errorf("forwarding headers not stripped: XFF=%q XRI=%q TCI=%q", leftoverXFF, leftoverXRI, leftoverTCI)
			}
		})
	}
}

func TestRequestLogger_RedactsUnmatchedPath(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	h := web.RequestLogger(logger)(http.NotFoundHandler())

	req := httptest.NewRequest(http.MethodGet, "/reset/super-secret-token-12345/typo?code=secret", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	logged := buf.String()
	if strings.Contains(logged, "super-secret-token-12345") || strings.Contains(logged, "code=secret") {
		t.Errorf("unmatched path or query leaked into request log: %s", logged)
	}
	if !strings.Contains(logged, `"route":"<unmatched>"`) {
		t.Errorf("expected <unmatched> route placeholder in log: %s", logged)
	}
}
