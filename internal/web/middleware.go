package web

import "net/http"

// SecurityHeaders returns a middleware that sets recommended security response
// headers on every request passing through it.
//
// Header rationale:
//   - X-Content-Type-Options: nosniff — prevents MIME-type sniffing attacks
//   - X-Frame-Options: DENY — prevents clickjacking via <iframe> (legacy browsers).
//     Aligned with CSP frame-ancestors 'none' which covers modern browsers.
//   - Referrer-Policy: strict-origin-when-cross-origin — limits URL leakage
//   - Permissions-Policy: disables geolocation, microphone, camera
//   - Content-Security-Policy: restricts resource loading to self only.
//     style-src includes 'unsafe-inline' because Bulma's generated HTML relies
//     on inline style attributes in some components. Scripts are 'self' only.
//     frame-ancestors 'none' disallows all framing (authoritative for modern browsers).
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			h.Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self'; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"font-src 'self'; "+
					"connect-src 'self'; "+
					"frame-ancestors 'none';")
			next.ServeHTTP(w, r)
		})
	}
}
