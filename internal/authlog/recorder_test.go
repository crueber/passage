package authlog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/testutil"
)

// failingAppender is a store stand-in whose writes always fail.
type failingAppender struct {
	calls int
}

func (f *failingAppender) Append(context.Context, *Event) error {
	f.calls++
	return errors.New("store is down")
}

func TestRecorder_FailingStoreIsNonFatal(t *testing.T) {
	t.Parallel()

	store := &failingAppender{}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	recorder := NewRecorder(store, logger)

	// Record has no return value; the assertion is that this returns instead
	// of panicking and that it did attempt the write.
	recorder.Record(context.Background(), Event{
		Event:   EventLoginSuccess,
		Outcome: OutcomeSuccess,
	})

	if store.calls != 1 {
		t.Errorf("Append call count = %d, want 1", store.calls)
	}
}

func TestRecorder_FillsIDAndCreatedAt(t *testing.T) {
	t.Parallel()
	database := testutil.NewTestDB(t)
	store := NewStore(database)
	recorder := NewRecorder(store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	before := time.Now().UTC()
	recorder.Record(context.Background(), Event{
		Event:   EventLoginFailure,
		Outcome: OutcomeFailure,
	})

	got, err := store.List(context.Background(), Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List: got %d events, want 1", len(got))
	}

	event := got[0]
	if len(event.ID) != 32 {
		t.Errorf("ID = %q, want 32 hex characters", event.ID)
	}
	if event.CreatedAt.Before(before.Add(-time.Second)) || event.CreatedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("CreatedAt = %v, want close to now", event.CreatedAt)
	}
}

func TestRecorder_TruncatesFields(t *testing.T) {
	t.Parallel()
	database := testutil.NewTestDB(t)
	store := NewStore(database)
	recorder := NewRecorder(store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	recorder.Record(context.Background(), Event{
		Event:     EventLoginFailure,
		Outcome:   OutcomeFailure,
		Username:  strings.Repeat("u", 400),
		UserAgent: strings.Repeat("a", 1000),
		Detail:    strings.Repeat("d", 2000),
		IP:        strings.Repeat("i", 200),
		UserID:    strings.Repeat("x", 200),
	})

	got, err := store.List(context.Background(), Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List: got %d events, want 1", len(got))
	}

	event := got[0]
	if n := len(event.Username); n != maxUsernameBytes {
		t.Errorf("Username length = %d, want %d", n, maxUsernameBytes)
	}
	if n := len(event.UserAgent); n != maxUserAgentBytes {
		t.Errorf("UserAgent length = %d, want %d", n, maxUserAgentBytes)
	}
	if n := len(event.Detail); n != maxDetailBytes {
		t.Errorf("Detail length = %d, want %d", n, maxDetailBytes)
	}
	if n := len(event.IP); n != maxIPBytes {
		t.Errorf("IP length = %d, want %d", n, maxIPBytes)
	}
	if n := len(event.UserID); n != maxUserIDBytes {
		t.Errorf("UserID length = %d, want %d", n, maxUserIDBytes)
	}
}

func TestRecorder_EmptyEventNameIsRejected(t *testing.T) {
	t.Parallel()

	store := &failingAppender{}
	recorder := NewRecorder(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recorder.Record(context.Background(), Event{Outcome: OutcomeFailure})

	if store.calls != 0 {
		t.Errorf("Append call count = %d, want 0", store.calls)
	}
}

func TestTruncate_DoesNotSplitRunes(t *testing.T) {
	t.Parallel()

	// "é" is two bytes; a 3-byte limit must back off to a single rune.
	if got := truncate("éé", 3); got != "é" {
		t.Errorf("truncate = %q, want %q", got, "é")
	}
	if got := truncate("abc", 10); got != "abc" {
		t.Errorf("truncate = %q, want %q", got, "abc")
	}
}

func TestClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{name: "ipv4 with port", remote: "192.0.2.10:54321", want: "192.0.2.10"},
		{name: "ipv6 with port", remote: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "no port", remote: "192.0.2.10", want: "192.0.2.10"},
		{name: "empty", remote: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login", nil)
			r.RemoteAddr = tc.remote
			if got := ClientIP(r); got != tc.want {
				t.Errorf("ClientIP(%q) = %q, want %q", tc.remote, got, tc.want)
			}
		})
	}

	if got := ClientIP(nil); got != "" {
		t.Errorf("ClientIP(nil) = %q, want empty", got)
	}
}
