package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ─── Allow unit tests ─────────────────────────────────────────────────────────

func TestAllow(t *testing.T) {
	t.Run("returns true for requests within the limit", func(t *testing.T) {
		l := New(3, time.Minute)
		for i := 0; i < 3; i++ {
			if !l.Allow("key") {
				t.Errorf("call %d: expected Allow to return true", i+1)
			}
		}
	})

	t.Run("returns false after the limit is exceeded", func(t *testing.T) {
		l := New(3, time.Minute)
		for i := 0; i < 3; i++ {
			l.Allow("key")
		}
		if l.Allow("key") {
			t.Error("expected Allow to return false after limit exceeded")
		}
	})

	t.Run("returns true again after the window expires", func(t *testing.T) {
		l := New(3, 50*time.Millisecond)
		for i := 0; i < 3; i++ {
			l.Allow("key")
		}
		// Confirm we're blocked.
		if l.Allow("key") {
			t.Error("expected Allow to return false before window expires")
		}
		// Wait for the window to expire.
		time.Sleep(60 * time.Millisecond)
		if !l.Allow("key") {
			t.Error("expected Allow to return true after window expired")
		}
	})

	t.Run("different keys are tracked independently", func(t *testing.T) {
		l := New(1, time.Minute)
		if !l.Allow("alice") {
			t.Error("expected alice's first request to be allowed")
		}
		if l.Allow("alice") {
			t.Error("expected alice's second request to be denied")
		}
		// bob has not made any requests yet — should be allowed.
		if !l.Allow("bob") {
			t.Error("expected bob's first request to be allowed")
		}
	})
}

// ─── Cleanup unit tests ───────────────────────────────────────────────────────

func TestCleanup(t *testing.T) {
	t.Run("removes stale entries after window expires", func(t *testing.T) {
		l := New(5, 50*time.Millisecond)
		l.Allow("ip-1")
		l.Allow("ip-2")

		if l.Len() != 2 {
			t.Errorf("expected 2 tracked keys before cleanup, got %d", l.Len())
		}

		// Wait for the window to expire, then cleanup.
		time.Sleep(60 * time.Millisecond)
		l.Cleanup()

		if l.Len() != 0 {
			t.Errorf("expected 0 tracked keys after cleanup, got %d", l.Len())
		}
	})

	t.Run("keeps active entries during cleanup", func(t *testing.T) {
		l := New(5, time.Minute)
		l.Allow("active")

		l.Cleanup()

		if l.Len() != 1 {
			t.Errorf("expected 1 active key to survive cleanup, got %d", l.Len())
		}
	})
}

// ─── Middleware tests ─────────────────────────────────────────────────────────

func TestMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("returns 200 when within limit", func(t *testing.T) {
		l := New(5, time.Minute)
		handler := Middleware(l)(next)

		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("returns 429 when limit exceeded", func(t *testing.T) {
		l := New(2, time.Minute)
		handler := Middleware(l)(next)

		for i := 0; i < 2; i++ {
			r := httptest.NewRequest(http.MethodPost, "/login", nil)
			r.RemoteAddr = "192.0.2.2:1234"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
		}

		// Third request should be rate-limited.
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.RemoteAddr = "192.0.2.2:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429, got %d", w.Code)
		}
		if w.Header().Get("Retry-After") == "" {
			t.Error("expected Retry-After header to be set")
		}
	})

	t.Run("returns JSON 429 for non-HTML clients", func(t *testing.T) {
		l := New(1, time.Minute)
		handler := Middleware(l)(next)

		// Exhaust the limit.
		r1 := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
		r1.RemoteAddr = "192.0.2.3:1234"
		r1.Header.Set("Accept", "application/json")
		handler.ServeHTTP(httptest.NewRecorder(), r1)

		// Rate-limited request.
		r2 := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
		r2.RemoteAddr = "192.0.2.3:1234"
		r2.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r2)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429, got %d", w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
	})

	t.Run("returns HTML 429 for browser clients", func(t *testing.T) {
		l := New(1, time.Minute)
		handler := Middleware(l)(next)

		// Exhaust the limit.
		r1 := httptest.NewRequest(http.MethodPost, "/login", nil)
		r1.RemoteAddr = "192.0.2.4:1234"
		r1.Header.Set("Accept", "text/html,application/xhtml+xml")
		handler.ServeHTTP(httptest.NewRecorder(), r1)

		// Rate-limited request.
		r2 := httptest.NewRequest(http.MethodPost, "/login", nil)
		r2.RemoteAddr = "192.0.2.4:1234"
		r2.Header.Set("Accept", "text/html,application/xhtml+xml")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r2)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429, got %d", w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if ct != "text/html; charset=utf-8" {
			t.Errorf("expected Content-Type text/html; charset=utf-8, got %q", ct)
		}
	})

	t.Run("returns HTML 429 when no Accept header (browser default)", func(t *testing.T) {
		l := New(1, time.Minute)
		handler := Middleware(l)(next)

		// Exhaust the limit.
		r1 := httptest.NewRequest(http.MethodPost, "/login", nil)
		r1.RemoteAddr = "192.0.2.5:1234"
		// No Accept header set — simulates a raw form POST with no explicit Accept.
		handler.ServeHTTP(httptest.NewRecorder(), r1)

		// Rate-limited request.
		r2 := httptest.NewRequest(http.MethodPost, "/login", nil)
		r2.RemoteAddr = "192.0.2.5:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r2)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429, got %d", w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if ct != "text/html; charset=utf-8" {
			t.Errorf("expected Content-Type text/html; charset=utf-8, got %q", ct)
		}
	})
}

// ─── clientIP unit tests ──────────────────────────────────────────────────────

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xRealIP    string
		xff        string
		want       string
	}{
		{
			name:       "uses X-Real-IP when set",
			remoteAddr: "10.0.0.1:1234",
			xRealIP:    "203.0.113.5",
			want:       "203.0.113.5",
		},
		{
			name:       "uses first entry of X-Forwarded-For",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.10, 10.0.0.2",
			want:       "203.0.113.10",
		},
		{
			name:       "uses RemoteAddr when no forwarding headers",
			remoteAddr: "192.0.2.99:5678",
			want:       "192.0.2.99",
		},
		{
			name:       "X-Real-IP takes priority over X-Forwarded-For",
			remoteAddr: "10.0.0.1:1234",
			xRealIP:    "203.0.113.1",
			xff:        "203.0.113.2",
			want:       "203.0.113.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xRealIP != "" {
				r.Header.Set("X-Real-IP", tc.xRealIP)
			}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			got := clientIP(r)
			if got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
