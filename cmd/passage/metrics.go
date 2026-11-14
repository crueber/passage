package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/metrics"
)

// countReader counts rows for one metric gauge. It is defined here at the
// wiring layer, together with the adapters below, so internal/metrics stays
// independent of the domain packages.
type countReader interface {
	Count(ctx context.Context) (int, error)
}

// activeSessionReader counts sessions that have not passed their absolute
// expiry.
type activeSessionReader interface {
	CountActive(ctx context.Context) (int, error)
}

// serverMetrics is the metrics registry plus the counter handles the server
// increments on request and authentication paths.
//
// Gauges are callbacks rather than stored values: they run a COUNT query at
// scrape time, so a gauge can never be stale or disagree with the database.
type serverMetrics struct {
	reg             *metrics.Registry
	authEvents      *metrics.Counter
	sessionsCreated *metrics.Counter
	sessionsRevoked *metrics.Counter
	requests        *metrics.Counter
}

// newServerMetrics registers the complete Passage metric set. Every counter is
// created here so the full exposition is declared even before the first event.
func newServerMetrics(
	logger *slog.Logger,
	buildVersion string,
	started time.Time,
	users countReader,
	apps countReader,
	sessions activeSessionReader,
) *serverMetrics {
	reg := metrics.New(logger)

	m := &serverMetrics{
		reg: reg,
		authEvents: reg.Counter(
			"passage_auth_events_total",
			"Authentication events recorded, by event name and outcome.",
			"event", "outcome",
		),
		sessionsCreated: reg.Counter(
			"passage_sessions_created_total",
			"Sessions created since the process started.",
		),
		sessionsRevoked: reg.Counter(
			"passage_sessions_revoked_total",
			"Explicit session revokes since the process started (a bulk revoke counts once).",
		),
		requests: reg.Counter(
			"passage_http_requests_total",
			"HTTP requests served, by method and response status code.",
			"method", "status",
		),
	}

	reg.Gauge("passage_users",
		"User accounts, including inactive ones.", nil,
		countGauge(users.Count))
	reg.Gauge("passage_apps",
		"Applications, including inactive ones.", nil,
		countGauge(apps.Count))
	reg.Gauge("passage_active_sessions",
		"Sessions that have not passed their absolute expiry.", nil,
		countGauge(sessions.CountActive))
	reg.Gauge("passage_process_start_time_seconds",
		"Start time of the process since the unix epoch in seconds.", nil,
		func(context.Context) ([]metrics.Sample, error) {
			return []metrics.Sample{{Value: float64(started.UnixNano()) / 1e9}}, nil
		})
	reg.Gauge("passage_build_info",
		"Build information about the running Passage binary; the value is always 1.",
		[]string{"version"},
		func(context.Context) ([]metrics.Sample, error) {
			return []metrics.Sample{{Values: []string{buildVersion}, Value: 1}}, nil
		})

	return m
}

// countGauge adapts a COUNT query to a gauge callback. The error is handed to
// the registry, which logs it and omits that family for the scrape rather than
// publishing a misleading zero.
func countGauge(count func(context.Context) (int, error)) metrics.GaugeFunc {
	return func(ctx context.Context) ([]metrics.Sample, error) {
		n, err := count(ctx)
		if err != nil {
			return nil, err
		}
		return []metrics.Sample{{Value: float64(n)}}, nil
	}
}

// SessionCreated implements session.SessionCounter.
func (m *serverMetrics) SessionCreated() { m.sessionsCreated.Inc() }

// SessionRevoked implements session.SessionCounter.
func (m *serverMetrics) SessionRevoked() { m.sessionsRevoked.Inc() }

// authEventCounter is the auth log recorder's second sink: it counts every
// recorded event and then forwards it to the next sink (the security webhook,
// when one is configured).
//
// It runs on the authentication path, so it does exactly two things and never
// blocks: an atomic increment followed by the already-asynchronous webhook
// hand-off. Counting happens even when the store write failed — the event
// still happened.
type authEventCounter struct {
	counter *metrics.Counter
	next    authlog.Notifier
}

// Notify implements authlog.Notifier.
func (a authEventCounter) Notify(event authlog.Event) {
	a.counter.Inc(event.Event, event.Outcome)
	if a.next != nil {
		a.next.Notify(event)
	}
}
