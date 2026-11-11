package metrics

import (
	"net/http"
	"strconv"
	"strings"
)

// knownMethods is the set of HTTP methods that get their own series. Anything
// else — an extension method, an empty string, or garbage from a malformed
// request line — is counted as "other" so the label set stays bounded.
var knownMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodPost:    {},
	http.MethodPut:     {},
	http.MethodPatch:   {},
	http.MethodDelete:  {},
	http.MethodOptions: {},
	http.MethodTrace:   {},
	http.MethodConnect: {},
}

// RequestMethod maps an HTTP method to a bounded metric label value.
//
// Only the method is ever recorded, never the path: a path label would give an
// attacker (or an unlucky crawler) unbounded cardinality in the time series
// database. Uppercasing first follows RFC 9110, which defines methods as
// case-sensitive tokens but is universally used uppercase.
func RequestMethod(method string) string {
	upper := strings.ToUpper(strings.TrimSpace(method))
	if _, ok := knownMethods[upper]; ok {
		return upper
	}
	return "other"
}

// HTTPMiddleware counts every request passing through it by method and status
// code. It is deliberately placed so that it also sees the status written by a
// recovering panic handler.
func HTTPMiddleware(requests *Counter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, req)
			requests.Inc(RequestMethod(req.Method), strconv.Itoa(rec.statusCode()))
		})
	}
}

// statusRecorder captures the status code a handler writes while passing the
// response through unchanged.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the final status code. Informational responses (1xx,
// for example 103 Early Hints) are forwarded but do not become the final
// status, matching how net/http treats them.
func (r *statusRecorder) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		r.ResponseWriter.WriteHeader(code)
		return
	}
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write records an implicit 200 for handlers that never call WriteHeader.
func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying writer so http.ResponseController can reach
// Flush, Hijack, and deadlines through this wrapper.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Flush implements http.Flusher for handlers that assert on it directly.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// statusCode returns the recorded status, defaulting to 200 for handlers that
// wrote nothing at all.
func (r *statusRecorder) statusCode() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
