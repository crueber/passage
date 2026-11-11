package metrics

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestCounter_IncAndAdd(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	c := reg.Counter("events_total", "Events.", "kind")
	c.Inc("a")
	c.Inc("a")
	c.Add(3, "b")

	got := expose(t, reg)
	for _, want := range []string{
		`events_total{kind="a"} 2`,
		`events_total{kind="b"} 3`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("exposition is missing %q:\n%s", want, got)
		}
	}
}

func TestCounter_ZeroValueIsExposedOnFirstIncrement(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	reg.Counter("events_total", "Events.", "kind").Inc("a")

	if got := expose(t, reg); !strings.Contains(got, `events_total{kind="a"} 1`) {
		t.Errorf("first increment must create the series, got:\n%s", got)
	}
}

func TestCounter_WrongLabelCountIsDropped(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	c := reg.Counter("events_total", "Events.", "event", "outcome")

	// Neither call may panic inside a request, and neither may create a series.
	c.Inc("too-few")
	c.Inc("too", "many", "values")

	if got := expose(t, reg); strings.Contains(got, "events_total{") {
		t.Errorf("mis-labelled increments must be dropped, got:\n%s", got)
	}
}

func TestCounter_ConcurrentIncrements(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	c := reg.Counter("events_total", "Events.", "kind")

	const goroutines = 8
	const perGoroutine = 250

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				c.Inc("a")
			}
		}()
	}

	// Scrape concurrently with the increments: this must not race (run with
	// -race) and must not lose a completed increment once the writers finish.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			var b strings.Builder
			if err := reg.WriteText(context.Background(), &b); err != nil {
				t.Errorf("WriteText during increments: %v", err)
				return
			}
		}
	}()

	wg.Wait()
	<-done

	got := expose(t, reg)
	want := `events_total{kind="a"} 2000`
	if !strings.Contains(got, want) {
		t.Errorf("exposition is missing %q:\n%s", want, got)
	}
}

func TestGauge_SamplesAreSortedAndLabelled(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	reg.Gauge("g", "Gauge.", []string{"name"}, func(context.Context) ([]Sample, error) {
		return []Sample{
			{Values: []string{"c"}, Value: 3},
			{Values: []string{"a"}, Value: 1},
			{Values: []string{"b"}, Value: 2},
		}, nil
	})

	got := expose(t, reg)
	want := []string{`g{name="a"} 1`, `g{name="b"} 2`, `g{name="c"} 3`}
	last := -1
	for _, line := range want {
		idx := strings.Index(got, line)
		if idx < 0 {
			t.Fatalf("exposition is missing %q:\n%s", line, got)
		}
		if idx <= last {
			t.Errorf("%q appears out of order:\n%s", line, got)
		}
		last = idx
	}
}

func TestRegistry_RegistrationValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		metric string
		labels []string
	}{
		{name: "empty name", metric: "", labels: nil},
		{name: "name with dash", metric: "bad-name", labels: nil},
		{name: "name starting with a digit", metric: "2fast", labels: nil},
		{name: "label with colon", metric: "ok_total", labels: []string{"a:b"}},
		{name: "duplicate label", metric: "ok_total", labels: []string{"a", "a"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := newTestRegistry()
			defer func() {
				if recover() == nil {
					t.Errorf("registering %q with labels %v must panic", tc.metric, tc.labels)
				}
			}()
			reg.Counter(tc.metric, "help", tc.labels...)
		})
	}
}

func TestRegistry_DuplicateFamilyPanics(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	reg.Counter("dup_total", "First.")

	defer func() {
		if recover() == nil {
			t.Error("registering the same metric name twice must panic")
		}
	}()
	reg.Counter("dup_total", "Second.")
}

func TestRegistry_GaugeRequiresCallback(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	defer func() {
		if recover() == nil {
			t.Error("registering a gauge without a callback must panic")
		}
	}()
	reg.Gauge("g", "Gauge.", nil, nil)
}
