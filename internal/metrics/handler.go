package metrics

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// HandlerOptions configures the /metrics endpoint.
type HandlerOptions struct {
	// Enabled serves metrics. When false the handler answers 404 for every
	// request, so the route can be registered unconditionally and the
	// endpoint's existence follows configuration alone.
	Enabled bool

	// Token, when non-empty, requires the request to carry
	// "Authorization: Bearer <token>". The token is never logged and is
	// compared in constant time. Empty leaves the endpoint unauthenticated
	// (the usual case behind a reverse proxy or on a private network).
	Token string
}

// Handler returns the /metrics endpoint. It serves the Prometheus text
// exposition format, and is cheap by construction: the response is gathered
// once per request and buffered, and every gauge is a COUNT-query callback.
func (r *Registry) Handler(opts HandlerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !opts.Enabled {
			http.NotFound(w, req)
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if opts.Token != "" && !validBearer(req.Header.Get("Authorization"), opts.Token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Gather into memory before writing a single byte: a gauge failure
		// mid-stream would otherwise leave a truncated exposition that a
		// scraper could mistake for a healthy one.
		var buf bytes.Buffer
		if err := r.WriteText(req.Context(), &buf); err != nil {
			http.Error(w, "failed to render metrics", http.StatusInternalServerError)
			return
		}

		h := w.Header()
		h.Set("Content-Type", contentType)
		h.Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		// A scrape client that disconnects mid-response is not an error worth
		// reporting: there is no partial-state risk and nobody to tell.
		_, _ = w.Write(buf.Bytes())
	})
}

// validBearer reports whether header is "Bearer <token>" for token. Both sides
// are hashed first so the comparison is constant time even when an attacker
// presents a value of a different length.
func validBearer(header, token string) bool {
	scheme, credential, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return false
	}
	got := sha256.Sum256([]byte(credential))
	want := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}
