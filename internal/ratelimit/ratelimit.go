package ratelimit

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/crueber/passage/internal/web"
)

// maxClientIPKeyBytes bounds the in-memory limiter key length.
const maxClientIPKeyBytes = 128

// window tracks request timestamps within a sliding time window for one key.
type window struct {
	mu         sync.Mutex
	timestamps []time.Time
	deleted    bool
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

// SetConfig changes the limit and window at runtime, clearing the tracked
// windows so the old counter values cannot leak into the new policy. It is
// called after an admin settings save; no restart is involved.
func (l *Limiter) SetConfig(limit int, period time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.limit == limit && l.period == period {
		return
	}
	l.limit = limit
	l.period = period
	l.windows = make(map[string]*window)
}

// RetryAfter returns the current window, used for the Retry-After header.
func (l *Limiter) RetryAfter() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.period
}

// Allow returns true if the key is within the rate limit, false if exceeded.
// A limit or period <= 0 disables rate limiting and allows every request.
// Allowed requests are recorded; denied requests are not (the window already
// has limit entries so no additional recording is needed).
func (l *Limiter) Allow(key string) bool {
	for {
		l.mu.Lock()
		limit, period := l.limit, l.period
		if limit <= 0 || period <= 0 {
			l.mu.Unlock()
			return true
		}
		w, ok := l.windows[key]
		if !ok {
			w = &window{}
			l.windows[key] = w
		}
		l.mu.Unlock()

		now := time.Now()
		cutoff := now.Add(-period)

		w.mu.Lock()
		if w.deleted {
			w.mu.Unlock()
			continue
		}

		// Remove timestamps outside the window.
		valid := w.timestamps[:0]
		for _, ts := range w.timestamps {
			if ts.After(cutoff) {
				valid = append(valid, ts)
			}
		}
		w.timestamps = valid

		if len(w.timestamps) >= limit {
			w.mu.Unlock()
			return false
		}
		w.timestamps = append(w.timestamps, now)
		w.mu.Unlock()
		return true
	}
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
	l.mu.Lock()
	period := l.period
	cutoff := time.Now().Add(-period)
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
		if !hasRecent {
			w.deleted = true
			delete(l.windows, key)
		}
		w.mu.Unlock()
	}
}

// Middleware returns a chi middleware that applies rate limiting based on the
// client's IP address (resolved upstream by web.TrustedRealIP into RemoteAddr).
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
				retryAfter := fmt.Sprintf("%.0f", l.RetryAfter().Seconds())
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

// clientIP extracts the resolved client IP from r.RemoteAddr using the shared
// web.ClientIP helper. Forwarding headers are resolved and stripped once at
// the router boundary by web.TrustedRealIP so rate limiting, access policies,
// and audit logs always agree on the client address.
func clientIP(r *http.Request) string {
	return clampKey(web.ClientIP(r))
}

func clampKey(s string) string {
	if len(s) > maxClientIPKeyBytes {
		return s[:maxClientIPKeyBytes]
	}
	return s
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
