package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scrape performs one request against the handler and returns the response
// recorder.
func scrape(t *testing.T, h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_EnabledAndAuth(t *testing.T) {
	t.Parallel()

	const token = "s3cret-token"

	tests := []struct {
		name       string
		opts       HandlerOptions
		authHeader string
		wantStatus int
	}{
		{
			name:       "disabled answers 404",
			opts:       HandlerOptions{Enabled: false},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "disabled answers 404 even with a valid token",
			opts:       HandlerOptions{Enabled: false, Token: token},
			authHeader: "Bearer " + token,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "enabled without a token is open",
			opts:       HandlerOptions{Enabled: true},
			wantStatus: http.StatusOK,
		},
		{
			name:       "enabled with a token rejects a missing header",
			opts:       HandlerOptions{Enabled: true, Token: token},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "enabled with a token rejects a wrong token",
			opts:       HandlerOptions{Enabled: true, Token: token},
			authHeader: "Bearer not-the-token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "enabled with a token rejects a shorter token",
			opts:       HandlerOptions{Enabled: true, Token: token},
			authHeader: "Bearer s3cret",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "enabled with a token rejects the basic scheme",
			opts:       HandlerOptions{Enabled: true, Token: token},
			authHeader: "Basic " + token,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "enabled with a token rejects a bare credential",
			opts:       HandlerOptions{Enabled: true, Token: token},
			authHeader: token,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "correct token is accepted",
			opts:       HandlerOptions{Enabled: true, Token: token},
			authHeader: "Bearer " + token,
			wantStatus: http.StatusOK,
		},
		{
			name:       "scheme is case-insensitive",
			opts:       HandlerOptions{Enabled: true, Token: token},
			authHeader: "bearer " + token,
			wantStatus: http.StatusOK,
		},
		{
			name:       "extra spaces around the credential are tolerated",
			opts:       HandlerOptions{Enabled: true, Token: token},
			authHeader: "Bearer   " + token + "  ",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reg := newTestRegistry()
			reg.Counter("passage_sessions_created_total", "Sessions created.").Inc()

			var headers map[string]string
			if tc.authHeader != "" {
				headers = map[string]string{"Authorization": tc.authHeader}
			}
			rec := scrape(t, reg.Handler(tc.opts), http.MethodGet, "/metrics", headers)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}

			if tc.wantStatus == http.StatusUnauthorized {
				want := `Bearer realm="metrics"`
				if got := rec.Header().Get("WWW-Authenticate"); got != want {
					t.Errorf("WWW-Authenticate = %q, want %q", got, want)
				}
			}
			// The token must never be echoed back, whatever the outcome.
			if strings.Contains(rec.Body.String(), token) {
				t.Errorf("response body leaks the token: %q", rec.Body.String())
			}
		})
	}
}

func TestHandler_ContentType(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	rec := scrape(t, reg.Handler(HandlerOptions{Enabled: true}), http.MethodGet, "/metrics", nil)

	if got, want := rec.Header().Get("Content-Type"), contentType; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if got, want := contentType, "text/plain; version=0.0.4; charset=utf-8"; got != want {
		t.Errorf("content type constant = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestHandler_ServesRegisteredMetrics(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	c := reg.Counter("passage_auth_events_total", "Events.", "event", "outcome")
	c.Inc("login.success", "success")
	c.Inc("login.failure", "failure")
	reg.Gauge("passage_users", "Users.", nil, constGauge(7))

	rec := scrape(t, reg.Handler(HandlerOptions{Enabled: true}), http.MethodGet, "/metrics", nil)
	body := rec.Body.String()

	for _, want := range []string{
		`passage_auth_events_total{event="login.failure",outcome="failure"} 1`,
		`passage_auth_events_total{event="login.success",outcome="success"} 1`,
		"passage_users 7",
		"# TYPE passage_auth_events_total counter",
		"# TYPE passage_users gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q:\n%s", want, body)
		}
	}
}

func TestHandler_Methods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method     string
		wantStatus int
	}{
		{method: http.MethodGet, wantStatus: http.StatusOK},
		{method: http.MethodHead, wantStatus: http.StatusOK},
		{method: http.MethodPost, wantStatus: http.StatusMethodNotAllowed},
		{method: http.MethodDelete, wantStatus: http.StatusMethodNotAllowed},
	}

	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			reg := newTestRegistry()
			reg.Counter("c_total", "C.").Inc()
			rec := scrape(t, reg.Handler(HandlerOptions{Enabled: true}), tc.method, "/metrics", nil)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusMethodNotAllowed {
				if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
					t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
				}
			}
		})
	}
}

// TestHandler_HeadHasNoBody checks that a HEAD scrape (used by some proxies for
// health checks) returns headers but no body through a real server, where
// net/http strips it.
func TestHandler_HeadHasNoBody(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	reg.Counter("c_total", "C.").Inc()

	srv := httptest.NewServer(reg.Handler(HandlerOptions{Enabled: true}))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Head(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("HEAD /metrics: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("HEAD body = %q, want empty", body)
	}
}

func TestValidBearer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		token  string
		want   bool
	}{
		{name: "exact", header: "Bearer tok", token: "tok", want: true},
		{name: "lowercase scheme", header: "bearer tok", token: "tok", want: true},
		{name: "empty header", header: "", token: "tok", want: false},
		{name: "scheme only", header: "Bearer", token: "tok", want: false},
		{name: "empty credential", header: "Bearer   ", token: "tok", want: false},
		{name: "different scheme", header: "Token tok", token: "tok", want: false},
		{name: "different length", header: "Bearer tokentoken", token: "tok", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := validBearer(tc.header, tc.token); got != tc.want {
				t.Errorf("validBearer(%q, %q) = %v, want %v", tc.header, tc.token, got, tc.want)
			}
		})
	}
}
