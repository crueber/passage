package user_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/ratelimit"
)

// hasSessionCookie reports whether the response set a non-empty session cookie.
func hasSessionCookie(rec *httptest.ResponseRecorder, name string) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

func TestHandler_PostLogin_PerAccountThrottle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("bad passwords lock the account and a correct password is rejected", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWithThrottle(t, true, 3, 15)
		if _, err := f.userSvc.Register(ctx, "alice", "alice@example.com", "password123"); err != nil {
			t.Fatalf("register alice: %v", err)
		}

		for i := 0; i < 3; i++ {
			rec := postLogin(t, f, "alice", "wrong-password")
			if rec.Code != http.StatusOK {
				t.Fatalf("failure %d status = %d, want 200", i, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "Invalid username or password.") {
				t.Errorf("failure %d body does not show the generic invalid message", i)
			}
		}

		rec := postLogin(t, f, "alice", "password123")
		if rec.Code != http.StatusOK {
			t.Fatalf("locked login status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Too many failed attempts. Try again in 15 minutes.") {
			t.Errorf("locked login body does not show the lockout message:\n%s", body)
		}
		if hasSessionCookie(rec, f.cfg.Session.CookieName) {
			t.Error("locked login set a session cookie; password verification should not run")
		}

		var failures, throttled int
		for _, e := range listAuthEvents(t, f) {
			switch e.Event {
			case authlog.EventLoginFailure:
				failures++
			case authlog.EventLoginThrottled:
				throttled++
				if e.Outcome != authlog.OutcomeThrottled {
					t.Errorf("login.throttled Outcome = %q, want %q", e.Outcome, authlog.OutcomeThrottled)
				}
				if e.Username != "alice" {
					t.Errorf("login.throttled Username = %q, want alice", e.Username)
				}
			}
		}
		if failures != 3 {
			t.Errorf("recorded %d login.failure events, want 3", failures)
		}
		if throttled != 1 {
			t.Errorf("recorded %d login.throttled events, want 1", throttled)
		}
	})

	t.Run("unknown usernames get the same lockout message", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWithThrottle(t, true, 2, 10)
		if _, err := f.userSvc.Register(ctx, "alice", "alice@example.com", "password123"); err != nil {
			t.Fatalf("register alice: %v", err)
		}

		lockMessage := func(username string) string {
			for i := 0; i < 2; i++ {
				if rec := postLogin(t, f, username, "wrong-password"); rec.Code != http.StatusOK {
					t.Fatalf("%s failure %d status = %d, want 200", username, i, rec.Code)
				}
			}
			rec := postLogin(t, f, username, "password123")
			if rec.Code != http.StatusOK {
				t.Fatalf("%s locked status = %d, want 200", username, rec.Code)
			}
			body := rec.Body.String()
			const prefix = "Too many failed attempts."
			idx := strings.Index(body, prefix)
			if idx < 0 {
				t.Fatalf("%s body has no lockout message:\n%s", username, body)
			}
			const suffix = "minutes."
			end := strings.Index(body[idx:], suffix)
			if end < 0 {
				t.Fatalf("%s lockout message has no %q suffix", username, suffix)
			}
			return body[idx : idx+end+len(suffix)]
		}

		known := lockMessage("alice")
		unknown := lockMessage("no-such-user")
		if known != unknown {
			t.Errorf("known lock message %q differs from unknown %q", known, unknown)
		}
		if !strings.Contains(known, "Try again in 10 minutes.") {
			t.Errorf("lock message %q does not state the remaining minutes", known)
		}
	})

	t.Run("success before the threshold clears the counter", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWithThrottle(t, true, 3, 15)
		if _, err := f.userSvc.Register(ctx, "bob", "bob@example.com", "password123"); err != nil {
			t.Fatalf("register bob: %v", err)
		}

		for i := 0; i < 2; i++ {
			if rec := postLogin(t, f, "bob", "wrong-password"); rec.Code != http.StatusOK {
				t.Fatalf("failure %d status = %d, want 200", i, rec.Code)
			}
		}
		if rec := postLogin(t, f, "bob", "password123"); rec.Code != http.StatusFound {
			t.Fatalf("successful login status = %d, want 302", rec.Code)
		}

		if _, err := f.throttleStore.Get(ctx, "bob"); !errors.Is(err, ratelimit.ErrNotFound) {
			t.Errorf("throttle row after success = %v, want ErrNotFound", err)
		}
	})

	t.Run("a lock expires and the correct password works again", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWithThrottle(t, true, 2, 15)
		if _, err := f.userSvc.Register(ctx, "carol", "carol@example.com", "password123"); err != nil {
			t.Fatalf("register carol: %v", err)
		}

		for i := 0; i < 2; i++ {
			if rec := postLogin(t, f, "carol", "wrong-password"); rec.Code != http.StatusOK {
				t.Fatalf("failure %d status = %d, want 200", i, rec.Code)
			}
		}
		if rec := postLogin(t, f, "carol", "password123"); rec.Code != http.StatusOK {
			t.Fatalf("locked login status = %d, want 200", rec.Code)
		}

		f.clock.Advance(15*time.Minute + time.Second)

		if rec := postLogin(t, f, "carol", "password123"); rec.Code != http.StatusFound {
			t.Fatalf("post-expiry login status = %d, want 302", rec.Code)
		}
	})

	t.Run("zero config disables throttling entirely", func(t *testing.T) {
		t.Parallel()
		f := newFullHandlerFixtureWithThrottle(t, true, 0, 15)
		if _, err := f.userSvc.Register(ctx, "dave", "dave@example.com", "password123"); err != nil {
			t.Fatalf("register dave: %v", err)
		}

		for i := 0; i < 8; i++ {
			if rec := postLogin(t, f, "dave", "wrong-password"); rec.Code != http.StatusOK {
				t.Fatalf("failure %d status = %d, want 200", i, rec.Code)
			}
		}
		if rec := postLogin(t, f, "dave", "password123"); rec.Code != http.StatusFound {
			t.Fatalf("successful login status = %d, want 302 (throttling disabled)", rec.Code)
		}
		if _, err := f.throttleStore.Get(ctx, "dave"); !errors.Is(err, ratelimit.ErrNotFound) {
			t.Errorf("throttle row = %v, want ErrNotFound when disabled", err)
		}
	})
}
