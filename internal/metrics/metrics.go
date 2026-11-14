// Package metrics provides Passage's Prometheus instrumentation: a small
// registry of counters and callback gauges plus a text-format encoder.
//
// It is deliberately tiny and standard-library only. There is no histogram
// support — every metric Passage publishes is a counter or a gauge — and the
// scrape path is kept cheap: counters live in atomics, and gauges are callbacks
// so a gauge can never disagree with the database it describes.
//
// Counters are incremented from authentication and request paths, so every
// method here is safe for concurrent use and never blocks, fails, or panics a
// caller. A metric that cannot be recorded is dropped and logged; it never
// propagates into an auth flow.
package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// kind is the Prometheus type of a metric family.
type kind string

const (
	kindCounter kind = "counter"
	kindGauge   kind = "gauge"
)

// Sample is one labelled measurement produced by a GaugeFunc.
type Sample struct {
	// Values are label values in the order of the family's label names.
	Values []string
	// Value is the measurement.
	Value float64
}

// GaugeFunc computes a gauge family's samples when a scrape happens.
//
// Returning an error skips that family for the scrape — the registry logs it
// and the remaining families are still served. A gauge error must never fail
// the scrape, and a gauge must never block for long: scrapes are serialised
// per client and share the process with authentication traffic.
type GaugeFunc func(ctx context.Context) ([]Sample, error)

// Registry holds every metric family Passage publishes.
//
// A Registry is safe for concurrent use. Families are registered once at
// startup and scraped concurrently afterwards; counter increments race with
// scrapes by design.
type Registry struct {
	logger   *slog.Logger
	mu       sync.RWMutex
	families map[string]*family
}

// New creates an empty registry. A nil logger falls back to slog.Default.
func New(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{
		logger:   logger,
		families: make(map[string]*family),
	}
}

// family is one metric family: a name, a help string, a type, and either a set
// of labelled counter series or a gauge callback.
type family struct {
	name       string
	help       string
	kind       kind
	labelNames []string
	gauge      GaugeFunc

	mu     sync.Mutex
	series map[string]*series
}

// series is one labelled counter value. The value is an atomic so an increment
// never waits on a concurrent scrape holding the family lock to enumerate
// series.
type series struct {
	values []string
	count  atomic.Uint64
}

// Counter is a handle to one counter family. All methods are safe for
// concurrent use.
type Counter struct {
	reg *Registry
	fam *family
}

// Counter registers a counter family and returns a handle for incrementing it.
//
// labelNames declares the family's label set: the values passed to Inc/Add are
// matched to those names positionally. Keep label values bounded — one series
// is allocated per distinct combination, forever (for example, never pass a
// URL path or a username).
//
// Registration is a startup-time operation with programmer-supplied constants,
// so a duplicate or malformed name panics rather than half-working at runtime.
func (r *Registry) Counter(name, help string, labelNames ...string) *Counter {
	fam := r.register(name, help, kindCounter, labelNames, nil)
	return &Counter{reg: r, fam: fam}
}

// Inc adds one to the counter series identified by values.
func (c *Counter) Inc(values ...string) {
	c.Add(1, values...)
}

// Add adds delta to the counter series identified by values.
//
// A label-value count that does not match the family's declared labels is a
// wiring bug; it is logged and dropped instead of panicking inside a request.
func (c *Counter) Add(delta uint64, values ...string) {
	if c == nil || c.fam == nil {
		return
	}
	if len(values) != len(c.fam.labelNames) {
		c.reg.logger.Warn("metrics: counter called with the wrong number of label values",
			"metric", c.fam.name,
			"labels", len(c.fam.labelNames),
			"values", len(values),
		)
		return
	}
	c.fam.seriesFor(values).count.Add(delta)
}

// Gauge registers a gauge family whose samples are computed by fn at scrape
// time. labelNames declares the family's label set; fn must return Values in
// that order. A nil fn is a wiring bug and panics at startup.
func (r *Registry) Gauge(name, help string, labelNames []string, fn GaugeFunc) {
	if fn == nil {
		panic(fmt.Sprintf("metrics: gauge %q registered without a callback", name))
	}
	r.register(name, help, kindGauge, labelNames, fn)
}

// register validates and stores a family. Registration happens once at startup
// with literal names, so invalid input is a programming error and panics.
func (r *Registry) register(name, help string, k kind, labelNames []string, fn GaugeFunc) *family {
	if !validMetricName(name) {
		panic(fmt.Sprintf("metrics: invalid metric name %q", name))
	}
	seen := make(map[string]struct{}, len(labelNames))
	for _, label := range labelNames {
		if !validLabelName(label) {
			panic(fmt.Sprintf("metrics: invalid label name %q on metric %q", label, name))
		}
		if _, dup := seen[label]; dup {
			panic(fmt.Sprintf("metrics: duplicate label %q on metric %q", label, name))
		}
		seen[label] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.families[name]; exists {
		panic(fmt.Sprintf("metrics: duplicate metric family %q", name))
	}
	fam := &family{
		name:       name,
		help:       help,
		kind:       k,
		labelNames: slices.Clone(labelNames),
		gauge:      fn,
		series:     make(map[string]*series),
	}
	r.families[name] = fam
	return fam
}

// seriesFor returns the series for values, creating it on first use. The
// returned pointer is stable for the life of the process, so increments need no
// lock beyond this lookup.
func (f *family) seriesFor(values []string) *series {
	key := seriesKey(values)

	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.series[key]
	if !ok {
		s = &series{values: slices.Clone(values)}
		f.series[key] = s
	}
	return s
}

// seriesKey encodes a label-value tuple as a map key without ambiguity: values
// containing the separator cannot collide with a different tuple.
func seriesKey(values []string) string {
	var b strings.Builder
	for _, v := range values {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}

// familySnapshot is an immutable copy of one family taken for a single scrape.
type familySnapshot struct {
	name       string
	help       string
	kind       kind
	labelNames []string
	samples    []sampleSnapshot
}

// sampleSnapshot is one pre-formatted sample line's worth of data.
type sampleSnapshot struct {
	values []string
	value  string
}

// snapshot copies every family so encoding never holds a lock and never races
// a counter increment. Families are returned sorted by name and samples sorted
// by label values, which makes the exposition deterministic across scrapes.
func (r *Registry) snapshot(ctx context.Context) []familySnapshot {
	r.mu.RLock()
	fams := make([]*family, 0, len(r.families))
	for _, fam := range r.families {
		fams = append(fams, fam)
	}
	r.mu.RUnlock()

	slices.SortFunc(fams, func(a, b *family) int { return strings.Compare(a.name, b.name) })

	out := make([]familySnapshot, 0, len(fams))
	for _, fam := range fams {
		snap := familySnapshot{
			name:       fam.name,
			help:       fam.help,
			kind:       fam.kind,
			labelNames: fam.labelNames,
		}

		switch fam.kind {
		case kindCounter:
			snap.samples = fam.counterSamples()
		case kindGauge:
			samples, err := fam.gauge(ctx)
			if err != nil {
				// A broken gauge must not take the whole scrape down, and a
				// zero would be a lie: leave the family out.
				r.logger.Warn("metrics: gauge callback failed", "metric", fam.name, "error", err)
				continue
			}
			snap.samples = gaugeSamples(samples)
		}

		out = append(out, snap)
	}
	return out
}

// counterSamples copies the family's series and formats their values.
func (f *family) counterSamples() []sampleSnapshot {
	f.mu.Lock()
	samples := make([]sampleSnapshot, 0, len(f.series))
	for _, s := range f.series {
		samples = append(samples, sampleSnapshot{
			values: slices.Clone(s.values),
			value:  strconv.FormatUint(s.count.Load(), 10),
		})
	}
	f.mu.Unlock()

	sortSamples(samples)
	return samples
}

// gaugeSamples formats the values returned by a gauge callback.
func gaugeSamples(got []Sample) []sampleSnapshot {
	samples := make([]sampleSnapshot, 0, len(got))
	for _, s := range got {
		samples = append(samples, sampleSnapshot{
			values: slices.Clone(s.Values),
			value:  strconv.FormatFloat(s.Value, 'f', -1, 64),
		})
	}
	sortSamples(samples)
	return samples
}

// sortSamples orders samples by their label values so output is stable.
func sortSamples(samples []sampleSnapshot) {
	slices.SortFunc(samples, func(a, b sampleSnapshot) int {
		for i := range a.values {
			if i >= len(b.values) {
				return 1
			}
			if c := strings.Compare(a.values[i], b.values[i]); c != 0 {
				return c
			}
		}
		return len(a.values) - len(b.values)
	})
}

// validMetricName reports whether name is a valid Prometheus metric name.
func validMetricName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == ':':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// validLabelName reports whether name is a valid Prometheus label name. Label
// names follow the metric-name rules without the reserved ":" namespace.
func validLabelName(name string) bool {
	if strings.ContainsRune(name, ':') {
		return false
	}
	return validMetricName(name)
}
