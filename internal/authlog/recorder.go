package authlog

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"
	"unicode/utf8"
)

// Field limits. Untrusted input is truncated before it is persisted so one
// oversized header cannot bloat the table or slow the admin page.
const (
	maxUsernameBytes  = 128
	maxUserAgentBytes = 256
	maxDetailBytes    = 512
	maxIPBytes        = 64
	maxUserIDBytes    = 64
)

// appender is the persistence interface the Recorder depends on. Defined at
// the consumer boundary so a failing store can be injected in tests.
type appender interface {
	Append(ctx context.Context, e *Event) error
}

// Recorder writes authentication events. Recording is best-effort: errors are
// logged and swallowed so a logging failure can never break an auth flow.
type Recorder struct {
	store  appender
	logger *slog.Logger
}

// NewRecorder creates a Recorder that writes through store and logs failures
// to logger.
func NewRecorder(store appender, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{store: store, logger: logger}
}

// Record writes e. ID and CreatedAt are generated when unset, and free-form
// fields are trimmed to their column limits. It never returns an error.
func (r *Recorder) Record(ctx context.Context, e Event) {
	if e.Event == "" {
		r.logger.Warn("authlog: refusing to record event without a name")
		return
	}

	if e.ID == "" {
		id, err := newID()
		if err != nil {
			r.logger.Warn("authlog: generate event id", "event", e.Event, "error", err)
			return
		}
		e.ID = id
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	e.Username = truncate(e.Username, maxUsernameBytes)
	e.UserAgent = truncate(e.UserAgent, maxUserAgentBytes)
	e.Detail = truncate(e.Detail, maxDetailBytes)
	e.IP = truncate(e.IP, maxIPBytes)
	e.UserID = truncate(e.UserID, maxUserIDBytes)

	if err := r.store.Append(ctx, &e); err != nil {
		// Deliberately non-fatal: the auth flow continues.
		r.logger.Warn("authlog: failed to record event",
			"event", e.Event,
			"outcome", e.Outcome,
			"error", err,
		)
	}
}

// ClientIP returns the client address for r without the port. The router
// applies chi's RealIP middleware, so r.RemoteAddr already reflects a trusted
// X-Forwarded-For when one is configured.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// truncate cuts s to at most max bytes without splitting a UTF-8 rune.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}
