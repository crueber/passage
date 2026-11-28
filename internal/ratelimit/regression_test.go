package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAllow_ZeroLimitDisablesRateLimiting verifies that setting the request
// limit to 0 disables rate limiting instead of denying every request.
func TestAllow_ZeroLimitDisablesRateLimiting(t *testing.T) {
	t.Parallel()

	l := New(0, time.Minute)
	for i := 0; i < 20; i++ {
		if !l.Allow("192.0.2.1") {
			t.Fatalf("call %d: limit=0 should allow all requests", i+1)
		}
	}

	// Switching an active limiter to 0 via SetConfig must also disable it.
	l2 := New(1, time.Minute)
	if !l2.Allow("192.0.2.2") {
		t.Fatal("first request should be allowed")
	}
	if l2.Allow("192.0.2.2") {
		t.Fatal("second request should be denied before disabling")
	}
	l2.SetConfig(0, time.Minute)
	if !l2.Allow("192.0.2.2") {
		t.Fatal("after SetConfig(0, ...), requests must be allowed")
	}
}

// TestClientIP_UsesResolvedRemoteAddrOnly verifies that the rate limiter relies
// strictly on r.RemoteAddr (as resolved by web.TrustedRealIP) and never
// re-reads raw forwarding headers.
func TestClientIP_UsesResolvedRemoteAddrOnly(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "198.51.100.7:4444"
	req.Header.Set("X-Real-IP", "203.0.113.99")
	req.Header.Set("X-Forwarded-For", "203.0.113.88")
	if got := clientIP(req); got != "198.51.100.7" {
		t.Errorf("clientIP = %q, want direct peer %q", got, "198.51.100.7")
	}
}
