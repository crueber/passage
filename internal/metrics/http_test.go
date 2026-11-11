package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/testutil"
)

func TestRequestMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		want   string
	}{
		{name: "get", method: "GET", want: "GET"},
		{name: "lowercase gets uppercased", method: "post", want: "POST"},
		{name: "known method with padding", method: " delete ", want: "DELETE"},
		{name: "extension method", method: "PROPFIND", want: "other"},
		{name: "garbage", method: "not a method", want: "other"},
		{name: "empty", method: "", want: "other"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RequestMethod(tc.method); got != tc.want {
				t.Errorf("RequestMethod(%q) = %q, want %q", tc.method, got, tc.want)
			}
		})
	}
}

func TestHTTPMiddleware_RecordsMethodAndStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		handler    http.HandlerFunc
		wantMethod string
		wantStatus string
	}{
		{
			name:   "implicit 200 from Write",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			},
			wantMethod: "GET",
			wantStatus: "200",
		},
		{
			name:   "no write at all defaults to 200",
			method: http.MethodHead,
			handler: func(http.ResponseWriter, *http.Request) {
			},
			wantMethod: "HEAD",
			wantStatus: "200",
		},
		{
			name:   "explicit 404",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, req *http.Request) {
				http.NotFound(w, req)
			},
			wantMethod: "GET",
			wantStatus: "404",
		},
		{
			name:   "explicit 204",
			method: http.MethodDelete,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			wantMethod: "DELETE",
			wantStatus: "204",
		},
		{
			name:   "server error",
			method: http.MethodPost,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			wantMethod: "POST",
			wantStatus: "500",
		},
		{
			name:   "provisional 1xx does not become the final status",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusEarlyHints)
				w.WriteHeader(http.StatusOK)
			},
			wantMethod: "GET",
			wantStatus: "200",
		},
		{
			name:   "unknown method is bucketed",
			method: "PROPFIND",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantMethod: "other",
			wantStatus: "200",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reg := newTestRegistry()
			requests := reg.Counter("passage_http_requests_total", "Requests.", "method", "status")

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/some/path", nil)
			HTTPMiddleware(requests)(tc.handler).ServeHTTP(rec, req)

			want := fmt.Sprintf(`passage_http_requests_total{method=%q,status=%q} 1`, tc.wantMethod, tc.wantStatus)
			got := expose(t, reg)
			if !strings.Contains(got, want) {
				t.Errorf("exposition is missing %q:\n%s", want, got)
			}
			// The path must never become a label: only method and status exist.
			if strings.Contains(got, "/some/path") {
				t.Errorf("request path leaked into metrics:\n%s", got)
			}
		})
	}
}

func TestHTTPMiddleware_CountsEachRequest(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	requests := reg.Counter("passage_http_requests_total", "Requests.", "method", "status")
	h := HTTPMiddleware(requests)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	for i := 0; i < 3; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}

	want := `passage_http_requests_total{method="GET",status="418"} 3`
	if got := expose(t, reg); !strings.Contains(got, want) {
		t.Errorf("exposition is missing %q:\n%s", want, got)
	}
}

// TestHTTPMiddleware_ResponseControllerStillWorks proves the wrapper does not
// break handlers that use http.ResponseController (Flush, deadlines) through
// the Unwrap contract.
func TestHTTPMiddleware_ResponseControllerStillWorks(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	requests := reg.Counter("passage_http_requests_total", "Requests.", "method", "status")

	// Flush lets the client return before the handler finishes, so the result
	// is passed over a channel rather than a plain variable.
	flushed := make(chan error, 1)
	h := HTTPMiddleware(requests)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flushed <- http.NewResponseController(w).Flush()
	}))

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if err := <-flushed; err != nil {
		t.Errorf("ResponseController.Flush through the wrapper: %v", err)
	}
}

// TestHandler_ScrapeDoesNotBlockDatabaseTraffic is the regression test for the
// single SQLite connection (db.Open calls SetMaxOpenConns(1)): gauge callbacks
// run COUNT queries on that one connection, so a scrape must never hold the
// connection while rendering or hold a registry lock while querying. Login
// traffic writes while scrapes are in flight and every scrape still answers.
func TestHandler_ScrapeDoesNotBlockDatabaseTraffic(t *testing.T) {
	t.Parallel()

	database := testutil.NewTestDB(t)

	reg := newTestRegistry()
	reg.Counter("passage_sessions_created_total", "Sessions created.").Inc()
	reg.Gauge("passage_users", "User accounts.", nil, func(ctx context.Context) ([]Sample, error) {
		var n int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
			return nil, err
		}
		return []Sample{{Value: float64(n)}}, nil
	})

	srv := httptest.NewServer(reg.Handler(HandlerOptions{Enabled: true}))
	t.Cleanup(srv.Close)
	client := &http.Client{Timeout: 10 * time.Second}

	// "Login traffic": each request needs the same single SQLite connection the
	// gauge callbacks use.
	const writes = 20
	writesDone := make(chan error, 1)
	go func() {
		for i := 0; i < writes; i++ {
			id := fmt.Sprintf("user-%02d", i)
			if _, err := database.ExecContext(context.Background(),
				`INSERT INTO users (id, username, email) VALUES (?, ?, ?)`,
				id, id, id+"@example.com",
			); err != nil {
				writesDone <- err
				return
			}
		}
		writesDone <- nil
	}()

	// Scrape concurrently with those writes.
	for i := 0; i < writes; i++ {
		resp, err := client.Get(srv.URL + "/metrics")
		if err != nil {
			t.Fatalf("scrape %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("scrape %d read body: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("scrape %d status = %d, want 200", i, resp.StatusCode)
		}
		if !strings.Contains(string(body), "passage_users ") {
			t.Fatalf("scrape %d did not include the database gauge:\n%s", i, body)
		}
	}

	select {
	case err := <-writesDone:
		if err != nil {
			t.Fatalf("login traffic failed while scraping: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("login traffic blocked while scraping")
	}

	// And the gauge sees every committed write.
	resp, err := client.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("final scrape: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("final scrape read body: %v", err)
	}
	if want := fmt.Sprintf("passage_users %d", writes); !strings.Contains(string(body), want) {
		t.Errorf("final scrape is missing %q:\n%s", want, body)
	}
}
