package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/crueber/passage/internal/config"
)

// ReturnCookieName is the short-lived cookie holding a post-login return path
// set by /auth/start and consumed by login/MFA/magic-link/passkey handlers.
const ReturnCookieName = "passage_rd"

// SafeReturnPath reports whether rd is a safe same-origin relative path
// suitable as a post-login redirect target. It rejects control characters
// (including TAB, CR, LF which browsers strip to turn "/\t/evil.com" into
// "//evil.com"), scheme-relative URLs ("//evil.com"), backslash tricks
// ("/\evil.com"), and any URL that parses with a scheme or host.
func SafeReturnPath(rd string) bool {
	if rd == "" || !strings.HasPrefix(rd, "/") {
		return false
	}
	for i := 0; i < len(rd); i++ {
		if rd[i] < 0x20 || rd[i] == 0x7f {
			return false
		}
	}
	if strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, `/\`) {
		return false
	}
	u, err := url.Parse(rd)
	if err != nil {
		return false
	}
	if u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil {
		return false
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, `/\`) {
		return false
	}
	return true
}

const returnCookieEncodedPrefix = "v1:"

// needsReturnCookieEncoding reports whether rd contains any character forbidden
// in an RFC 6265 cookie-octet (controls, space, '"', ',', ';', '\') or starts
// with our encoding prefix.
func needsReturnCookieEncoding(rd string) bool {
	if strings.HasPrefix(rd, returnCookieEncodedPrefix) {
		return true
	}
	for i := 0; i < len(rd); i++ {
		c := rd[i]
		if c <= 0x20 || c >= 0x7f || c == '"' || c == ',' || c == ';' || c == '\\' {
			return true
		}
	}
	return false
}

// SetReturnCookie stores a validated post-login return path in a short-lived
// HttpOnly cookie. Ordinary paths (including OAuth authorize URLs) are stored
// verbatim; paths containing RFC 6265 forbidden cookie-octets (commas,
// semicolons, quotes, spaces) are percent-encoded with a "v1:" prefix so
// net/http's cookie sanitizer never strips them.
func SetReturnCookie(w http.ResponseWriter, rd string, secure bool) {
	val := rd
	if needsReturnCookieEncoding(rd) {
		val = returnCookieEncodedPrefix + url.QueryEscape(rd)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     ReturnCookieName,
		Value:    val,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ReadReturnCookie reads and decodes the passage_rd cookie if present.
func ReadReturnCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(ReturnCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	if strings.HasPrefix(c.Value, returnCookieEncodedPrefix) {
		decoded, err := url.QueryUnescape(strings.TrimPrefix(c.Value, returnCookieEncodedPrefix))
		if err != nil {
			return "", false
		}
		return decoded, true
	}
	return c.Value, true
}

// ClearReturnCookie expires the passage_rd cookie if it was sent on r.
func ClearReturnCookie(w http.ResponseWriter, r *http.Request, secure bool) {
	if _, err := r.Cookie(ReturnCookieName); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     ReturnCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// SetSessionCookie writes the Passage session cookie onto w using the
// configured cookie name, Secure flag, and HttpOnly/SameSite=Lax invariants.
func SetSessionCookie(w http.ResponseWriter, sc config.SessionConfig, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sc.EffectiveCookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   sc.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the Passage session cookie on w.
func ClearSessionCookie(w http.ResponseWriter, sc config.SessionConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     sc.EffectiveCookieName(),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   sc.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClientIP returns the client IP address from r.RemoteAddr without the port.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// ParseTrustedProxies parses a list of CIDR prefixes or single IP addresses
// into normalized netip.Prefixes (with IPv4-mapped IPv6 addresses unmapped).
func ParseTrustedProxies(raw []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", entry, err)
			}
			addr := p.Addr().Unmap()
			bits := p.Bits()
			if p.Addr().Is4In6() && bits >= 96 {
				bits -= 96
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits).Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy IP %q: %w", entry, err)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

// TrustedRealIP replaces chi's unconditional RealIP middleware. Forwarding
// headers are honored ONLY when the direct TCP peer matches one of trusted.
//
// Resolution order when the direct peer is trusted:
//  1. X-Forwarded-For walked right-to-left skipping hops in trusted (rightmost
//     untrusted IP wins, or the leftmost valid hop if every hop is trusted).
//     Preferring XFF over X-Real-IP prevents a client-supplied X-Real-IP from
//     winning behind proxies (like Caddy or default nginx) that append to XFF
//     without overwriting X-Real-IP.
//  2. X-Real-IP (only when X-Forwarded-For yielded no valid IP).
//  3. True-Client-IP (only when neither XFF nor X-Real-IP yielded a valid IP).
//
// Forwarding headers are stripped from r.Header unconditionally after
// resolution so no downstream middleware or handler can read unverified values.
func TrustedRealIP(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer := ClientIP(r)
			if matchesTrusted(peer, trusted) {
				if ip := extractForwardedIP(r, trusted); ip != "" {
					r.RemoteAddr = ip
				}
			}
			r.Header.Del("X-Forwarded-For")
			r.Header.Del("X-Real-IP")
			r.Header.Del("True-Client-IP")
			next.ServeHTTP(w, r)
		})
	}
}

func matchesTrusted(ipStr string, trusted []netip.Prefix) bool {
	if len(trusted) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func extractForwardedIP(r *http.Request, trusted []netip.Prefix) string {
	// 1. Prefer X-Forwarded-For walked right-to-left across all header lines.
	if xffVals := r.Header.Values("X-Forwarded-For"); len(xffVals) > 0 {
		var parts []string
		for _, v := range xffVals {
			parts = append(parts, strings.Split(v, ",")...)
		}
		var leftmostValid string
		for i := len(parts) - 1; i >= 0; i-- {
			tok := strings.TrimSpace(parts[i])
			addr, err := netip.ParseAddr(tok)
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			leftmostValid = addr.String()
			if !matchesTrusted(leftmostValid, trusted) {
				return leftmostValid
			}
		}
		if leftmostValid != "" {
			return leftmostValid
		}
	}
	// 2. Fallback to X-Real-IP when no X-Forwarded-For was present.
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		if addr, err := netip.ParseAddr(xrip); err == nil {
			return addr.Unmap().String()
		}
	}
	// 3. Fallback to True-Client-IP.
	if tcip := strings.TrimSpace(r.Header.Get("True-Client-IP")); tcip != "" {
		if addr, err := netip.ParseAddr(tcip); err == nil {
			return addr.Unmap().String()
		}
	}
	return ""
}

// RequestLogger logs completed HTTP requests via slog instead of chi's stdlib
// logger, and never logs raw query strings or unmatched paths (preventing
// mistyped magic-link, password-reset, or invitation token URLs from reaching
// logs).
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}
			route := ""
			if rctx := chi.RouteContext(r.Context()); rctx != nil {
				route = rctx.RoutePattern()
			}
			if route == "" {
				// Never log raw unmatched paths: a mistyped token-bearing URL
				// (e.g. /reset/<token>/) would otherwise leak the secret token.
				route = "<unmatched>"
			}

			logger.Info("http request",
				"method", r.Method,
				"route", route,
				"status", status,
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"remote_ip", ClientIP(r),
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}

// StaticHandler serves embedded static assets with a strong ETag computed from
// the embedded file contents and Cache-Control headers so browsers revalidate
// instead of re-downloading CSS and JS on every page navigation.
func StaticHandler(staticFS fs.FS) http.Handler {
	etags := make(map[string]string)
	_ = fs.WalkDir(staticFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, readErr := fs.ReadFile(staticFS, path)
		if readErr != nil {
			return nil
		}
		sum := sha256.Sum256(data)
		etags[path] = `"` + hex.EncodeToString(sum[:8]) + `"`
		return nil
	})

	fileServer := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/")
		if tag, ok := etags[rel]; ok {
			w.Header().Set("ETag", tag)
			w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
			if match := r.Header.Get("If-None-Match"); match == tag || match == "W/"+tag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}
