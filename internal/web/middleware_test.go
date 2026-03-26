package web_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/web"
)

func TestSecurityHeaders(t *testing.T) {
	handler := web.SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	tests := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := w.Header().Get(tt.header)
			if got != tt.want {
				t.Errorf("header %s: got %q, want %q", tt.header, got, tt.want)
			}
		})
	}

	t.Run("Content-Security-Policy is present", func(t *testing.T) {
		csp := w.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Error("expected Content-Security-Policy header to be set")
		}
		// Verify it contains key directives.
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("CSP missing default-src 'self': %s", csp)
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP missing frame-ancestors 'none': %s", csp)
		}
	})

	t.Run("Permissions-Policy is present", func(t *testing.T) {
		pp := w.Header().Get("Permissions-Policy")
		if pp == "" {
			t.Error("expected Permissions-Policy header to be set")
		}
	})
}
