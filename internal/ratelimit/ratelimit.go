package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// window tracks request timestamps within a sliding time window for one key.
type window struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// Limiter is a sliding-window rate limiter keyed by string (IP address or username).
// It is safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	windows map[string]*window
	limit   int
	period  time.Duration
}

// New creates a Limiter allowing at most limit requests per period.
func New(limit int, period time.Duration) *Limiter {
	return &Limiter{
		windows: make(map[string]*window),
		limit:   limit,
		period:  period,
	}
}

// Allow returns true if the key is within the rate limit, false if exceeded.
// Allowed requests are recorded; denied requests are not (the window already
// has limit entries so no additional recording is needed).
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	w, ok := l.windows[key]
	if !ok {
		w = &window{}
		l.windows[key] = w
	}
	l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.period)

	w.mu.Lock()
	defer w.mu.Unlock()

	// Remove timestamps outside the window.
	valid := w.timestamps[:0]
	for _, ts := range w.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	w.timestamps = valid

	if len(w.timestamps) >= l.limit {
		return false
	}
	w.timestamps = append(w.timestamps, now)
	return true
}

// Len returns the number of keys currently tracked by the limiter.
// Intended for use in tests.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.windows)
}

// Cleanup removes entries for keys with no recent activity.
// Call periodically (e.g., every 5 minutes) to prevent unbounded memory growth.
func (l *Limiter) Cleanup() {
	cutoff := time.Now().Add(-l.period)

	l.mu.Lock()
	defer l.mu.Unlock()

	for key, w := range l.windows {
		w.mu.Lock()
		hasRecent := false
		for _, ts := range w.timestamps {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
		w.mu.Unlock()
		if !hasRecent {
			delete(l.windows, key)
		}
	}
}

// Middleware returns a chi middleware that applies rate limiting based on the
// client's IP address (extracted via X-Real-IP, X-Forwarded-For, or RemoteAddr).
//
// On limit exceeded:
//   - If the Accept header includes "text/html" or is absent (browser default),
//     renders a plain HTML 429 page.
//   - Otherwise, returns a JSON 429 response.
//
// A Retry-After header is always set (conservative estimate: full period in seconds).
func Middleware(l *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !l.Allow(ip) {
				retryAfter := fmt.Sprintf("%.0f", l.period.Seconds())
				w.Header().Set("Retry-After", retryAfter)
				// Check if client expects HTML.
				if acceptsHTML(r) {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = fmt.Fprintf(w,
						`<!DOCTYPE html><html><head><title>Too Many Requests</title></head>`+
							`<body><h1>Too Many Requests</h1>`+
							`<p>Too many attempts. Please wait %s seconds and try again.</p>`+
							`</body></html>`, retryAfter)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = fmt.Fprintf(w, `{"error":"too many requests","retry_after":%s}`, retryAfter)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the real client IP from the request.
// It trusts X-Real-IP and X-Forwarded-For headers, which is appropriate when
// Passage runs behind a trusted reverse proxy. If Passage is exposed directly
// to the internet without a proxy, these headers could be spoofed by clients.
// Uses X-Real-IP first, then X-Forwarded-For (first entry), then RemoteAddr.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can be a comma-separated list; take the first entry.
		for i, c := range xff {
			if c == ',' {
				return strings.TrimSpace(xff[:i])
			}
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// acceptsHTML returns true if the Accept header includes "text/html" or is absent
// (browsers that omit Accept should receive HTML).
func acceptsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return true
	}
	for _, part := range strings.Split(accept, ",") {
		if strings.Contains(strings.TrimSpace(part), "text/html") {
			return true
		}
	}
	return false
}
