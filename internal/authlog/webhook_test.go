package authlog

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crueber/passage/internal/testutil"
)

// syncBuffer is a goroutine-safe io.Writer for capturing slog output while the
// webhook worker is running.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// recordingAppender is a store stand-in that keeps every event it is given.
type recordingAppender struct {
	mu     sync.Mutex
	events []Event
}

func (a *recordingAppender) Append(_ context.Context, e *Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, *e)
	return nil
}

func (a *recordingAppender) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

func newTestLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// waitForLog polls until logs contains substr or five seconds pass.
func waitForLog(t *testing.T, logs *syncBuffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), substr) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("log never contained %q; logs:\n%s", substr, logs.String())
}

func TestNewWebhookNotifier_RejectsInvalidEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		timeout  time.Duration
	}{
		{name: "unsupported scheme", endpoint: "ftp://hooks.example.com/x", timeout: time.Second},
		{name: "relative path", endpoint: "/hooks", timeout: time.Second},
		{name: "no host", endpoint: "http://", timeout: time.Second},
		{name: "zero timeout", endpoint: "https://hooks.example.com/x", timeout: 0},
		{name: "negative timeout", endpoint: "https://hooks.example.com/x", timeout: -time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewWebhookNotifier(tc.endpoint, "", tc.timeout, nil); err == nil {
				t.Fatalf("NewWebhookNotifier(%q, %s): expected error, got nil", tc.endpoint, tc.timeout)
			}
		})
	}
}

func TestWebhookNotifier_DeliversPayload(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 11, 10, 12, 34, 56, 0, time.UTC)
	tests := []struct {
		name   string
		secret string
	}{
		{name: "unsigned", secret: ""},
		{name: "signed", secret: "top-secret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			type request struct {
				method      string
				contentType string
				signature   string
				body        []byte
			}
			received := make(chan request, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
				}
				received <- request{
					method:      r.Method,
					contentType: r.Header.Get("Content-Type"),
					signature:   r.Header.Get(webhookSignatureHeader),
					body:        body,
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			logger, _ := newTestLogger()
			notifier, err := NewWebhookNotifier(srv.URL, tc.secret, time.Second, logger)
			if err != nil {
				t.Fatalf("NewWebhookNotifier: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			notifier.Start(ctx)
			defer notifier.Close()

			store := &recordingAppender{}
			recorder := NewRecorder(store, notifier, logger)
			recorder.Record(context.Background(), Event{
				Event:     EventLoginFailure,
				Outcome:   OutcomeFailure,
				Username:  "alice",
				UserID:    "01f1b0a5",
				IP:        "192.0.2.10",
				UserAgent: "curl/8.5.0",
				Detail:    "invalid password",
				CreatedAt: created,
			})

			var req request
			select {
			case req = <-received:
			case <-time.After(5 * time.Second):
				t.Fatal("webhook endpoint was never called")
			}

			if req.method != http.MethodPost {
				t.Errorf("method = %q, want POST", req.method)
			}
			if got := req.contentType; got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}

			// Decode into a generic map so the test can assert the exact set of
			// keys, not just the fields it happens to know about.
			var payload map[string]string
			if err := json.Unmarshal(req.body, &payload); err != nil {
				t.Fatalf("decode payload %q: %v", req.body, err)
			}
			wantPayload := map[string]string{
				"event":      EventLoginFailure,
				"outcome":    OutcomeFailure,
				"username":   "alice",
				"user_id":    "01f1b0a5",
				"ip":         "192.0.2.10",
				"user_agent": "curl/8.5.0",
				"detail":     "invalid password",
				"created_at": "2026-11-10T12:34:56Z",
			}
			if len(payload) != len(wantPayload) {
				t.Errorf("payload has %d keys, want %d: %v", len(payload), len(wantPayload), payload)
			}
			for key, want := range wantPayload {
				if got := payload[key]; got != want {
					t.Errorf("payload[%q] = %q, want %q", key, got, want)
				}
			}

			if tc.secret == "" {
				if req.signature != "" {
					t.Errorf("%s = %q, want no header when no secret is configured", webhookSignatureHeader, req.signature)
				}
			} else {
				mac := hmac.New(sha256.New, []byte(tc.secret))
				mac.Write(req.body)
				want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
				if req.signature != want {
					t.Errorf("%s = %q, want %q", webhookSignatureHeader, req.signature, want)
				}
				if !strings.HasPrefix(req.signature, "sha256=") {
					t.Errorf("signature %q does not carry the sha256= prefix", req.signature)
				}
			}
		})
	}
}

func TestWebhookNotifier_Non2xxIsLoggedNotFatal(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	logger, logs := newTestLogger()
	notifier, err := NewWebhookNotifier(srv.URL, "", time.Second, logger)
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifier.Start(ctx)
	defer notifier.Close()

	store := &recordingAppender{}
	recorder := NewRecorder(store, notifier, logger)
	recorder.Record(context.Background(), Event{Event: EventLoginSuccess, Outcome: OutcomeSuccess})

	waitForLog(t, logs, "non-2xx")
	if !strings.Contains(logs.String(), "status=500") {
		t.Errorf("log does not report the status code; logs:\n%s", logs.String())
	}
	// The store remains authoritative and the auth flow is unaffected.
	if got := store.count(); got != 1 {
		t.Errorf("store appends = %d, want 1", got)
	}
}

func TestWebhookNotifier_DoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	followed := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	logger, logs := newTestLogger()
	notifier, err := NewWebhookNotifier(srv.URL, "secret", time.Second, logger)
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifier.Start(ctx)
	defer notifier.Close()

	recorder := NewRecorder(&recordingAppender{}, notifier, logger)
	recorder.Record(context.Background(), Event{Event: EventLoginFailure, Outcome: OutcomeFailure})

	// The 3xx is logged as a failed delivery instead of being followed.
	waitForLog(t, logs, "non-2xx")
	select {
	case <-followed:
		t.Error("redirect target was called; the webhook must not follow redirects")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRecorder_NilNotifierStillPersists(t *testing.T) {
	t.Parallel()

	database := testutil.NewTestDB(t)
	store := NewStore(database)
	logger, _ := newTestLogger()

	// No webhook configured: the recorder must behave exactly as before.
	recorder := NewRecorder(store, nil, logger)
	recorder.Record(context.Background(), Event{Event: EventLoginSuccess, Outcome: OutcomeSuccess})

	got, err := store.List(context.Background(), Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("stored events = %d, want 1", len(got))
	}
	if got[0].Event != EventLoginSuccess {
		t.Errorf("stored event = %q, want %q", got[0].Event, EventLoginSuccess)
	}
}

func TestRecorder_RecordDoesNotBlockOnSlowEndpoint(t *testing.T) {
	t.Parallel()

	handlerStarted := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerStarted <- struct{}{}
		// Far longer than the notifier's timeout: the request path must not
		// wait for this, and the worker must give up on its own.
		time.Sleep(750 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	logger, logs := newTestLogger()
	notifier, err := NewWebhookNotifier(srv.URL, "", 100*time.Millisecond, logger)
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifier.Start(ctx)
	defer notifier.Close()

	recorder := NewRecorder(&recordingAppender{}, notifier, logger)

	start := time.Now()
	recorder.Record(context.Background(), Event{Event: EventLoginFailure, Outcome: OutcomeFailure})
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("Record took %s with a slow endpoint; it must not block the request path", elapsed)
	}

	// The worker's per-request timeout must fire even though the handler is
	// still sleeping.
	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("endpoint was never called")
	}
	waitForLog(t, logs, "delivery failed")
	if !strings.Contains(logs.String(), "deadline exceeded") &&
		!strings.Contains(logs.String(), "Client.Timeout") {
		t.Errorf("log does not report the timeout; logs:\n%s", logs.String())
	}
}

func TestWebhookNotifier_OverflowDropsAndLogs(t *testing.T) {
	t.Parallel()

	logger, logs := newTestLogger()
	notifier, err := NewWebhookNotifier("https://hooks.example.com/passage", "", time.Second, logger)
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}

	// No worker is started, so the queue fills and every further Notify must
	// drop immediately rather than block.
	const extra = 44
	start := time.Now()
	for i := 0; i < webhookQueueSize+extra; i++ {
		notifier.Notify(Event{Event: EventLoginFailure, Outcome: OutcomeFailure})
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("filling an unread queue took %s; Notify must not block", elapsed)
	}

	if got := strings.Count(logs.String(), "queue full"); got != extra {
		t.Errorf("drop warnings = %d, want %d; logs:\n%s", got, extra, logs.String())
	}
	// Close is a no-op when the worker never started.
	notifier.Close()
}

func TestWebhookNotifier_CloseStopsWorker(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	logger, _ := newTestLogger()
	notifier, err := NewWebhookNotifier(srv.URL, "", time.Minute, logger)
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifier.Start(ctx)

	recorder := NewRecorder(&recordingAppender{}, notifier, logger)
	recorder.Record(context.Background(), Event{Event: EventLoginSuccess, Outcome: OutcomeSuccess})

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("endpoint was never called")
	}

	// Close must abort the in-flight request and return without waiting for
	// the receiver or for the one-minute timeout.
	closed := make(chan struct{})
	go func() {
		notifier.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Close did not return promptly")
	}
	close(release)
}
