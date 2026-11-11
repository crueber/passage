package metrics

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// testLogger returns a logger that discards everything, so a test that
// deliberately breaks a gauge does not print warnings.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestRegistry creates an empty registry backed by the discard logger.
func newTestRegistry() *Registry {
	return New(testLogger())
}

// expose renders the registry with a background context.
func expose(t *testing.T, reg *Registry) string {
	t.Helper()
	var b strings.Builder
	if err := reg.WriteText(context.Background(), &b); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	return b.String()
}

// constGauge returns a gauge callback that always reports one unlabelled value.
func constGauge(value float64) GaugeFunc {
	return func(context.Context) ([]Sample, error) {
		return []Sample{{Value: value}}, nil
	}
}

func TestWriteText_Exposition(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	requests := reg.Counter("passage_http_requests_total",
		"HTTP requests served, by method and response status code.", "method", "status")
	requests.Inc("POST", "500")
	requests.Inc("GET", "200")
	requests.Inc("GET", "200")
	reg.Gauge("passage_build_info", "Build information about the running binary.",
		[]string{"version"}, func(context.Context) ([]Sample, error) {
			return []Sample{{Values: []string{"1.2.3"}, Value: 1}}, nil
		})
	reg.Gauge("passage_users", "User accounts, including inactive ones.", nil, constGauge(3))

	want := strings.Join([]string{
		`# HELP passage_build_info Build information about the running binary.`,
		`# TYPE passage_build_info gauge`,
		`passage_build_info{version="1.2.3"} 1`,
		`# HELP passage_http_requests_total HTTP requests served, by method and response status code.`,
		`# TYPE passage_http_requests_total counter`,
		`passage_http_requests_total{method="GET",status="200"} 2`,
		`passage_http_requests_total{method="POST",status="500"} 1`,
		`# HELP passage_users User accounts, including inactive ones.`,
		`# TYPE passage_users gauge`,
		`passage_users 3`,
		``,
	}, "\n")

	if got := expose(t, reg); got != want {
		t.Errorf("exposition mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteText_LabelsAndFamiliesAreSorted(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	// Families deliberately registered out of order, and series incremented in
	// an order that is not the output order.
	reg.Counter("zebra_total", "z.", "kind").Inc("b")
	alpha := reg.Counter("alpha_total", "a.", "kind")
	alpha.Inc("z")
	alpha.Inc("a")
	reg.Gauge("middle", "m.", nil, constGauge(1))

	got := expose(t, reg)

	wantOrder := []string{
		"# HELP alpha_total",
		`alpha_total{kind="a"} 1`,
		`alpha_total{kind="z"} 1`,
		"# HELP middle",
		"middle 1",
		"# HELP zebra_total",
		`zebra_total{kind="b"} 1`,
	}
	last := -1
	for _, want := range wantOrder {
		idx := strings.Index(got, want)
		if idx < 0 {
			t.Fatalf("exposition is missing %q:\n%s", want, got)
		}
		if idx <= last {
			t.Errorf("%q appears out of order:\n%s", want, got)
		}
		last = idx
	}
}

func TestWriteText_EscapesHelpAndLabelValues(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	reg.Counter("escaped_total", "back\\slash and\nnewline", "detail").
		Inc("quote\" back\\slash newline\nend")

	got := expose(t, reg)

	wantHelp := `# HELP escaped_total back\\slash and\nnewline`
	if !strings.Contains(got, wantHelp) {
		t.Errorf("HELP line = %q, want it to contain %q", got, wantHelp)
	}
	// The label value must stay on one line: a raw newline inside it would
	// split the sample and corrupt every following line of the exposition.
	wantSample := `escaped_total{detail="quote\" back\\slash newline\nend"} 1`
	if !strings.Contains(got, wantSample) {
		t.Errorf("sample line = %q, want it to contain %q", got, wantSample)
	}
	if lines := strings.Count(got, "\n"); lines != 3 {
		t.Errorf("exposition has %d lines, want 3 (HELP, TYPE, sample):\n%s", lines, got)
	}
}

func TestWriteText_GaugeErrorSkipsOnlyThatFamily(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	reg.Counter("passage_sessions_created_total", "Sessions created.").Inc()
	reg.Gauge("passage_users", "User accounts.", nil, func(context.Context) ([]Sample, error) {
		return nil, io.ErrUnexpectedEOF
	})
	reg.Gauge("passage_apps", "Apps.", nil, constGauge(2))

	got := expose(t, reg)
	if strings.Contains(got, "passage_users") {
		t.Errorf("failed gauge must be omitted entirely, got:\n%s", got)
	}
	if !strings.Contains(got, `passage_sessions_created_total 1`) {
		t.Errorf("counter must still be exposed, got:\n%s", got)
	}
	if !strings.Contains(got, `passage_apps 2`) {
		t.Errorf("healthy gauge must still be exposed, got:\n%s", got)
	}
}

func TestWriteText_NoSamplesStillDeclaresFamily(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	reg.Counter("passage_sessions_revoked_total", "Sessions revoked.", "reason")

	got := expose(t, reg)
	if !strings.Contains(got, "# TYPE passage_sessions_revoked_total counter") {
		t.Errorf("a counter with no series must still declare HELP/TYPE, got:\n%s", got)
	}
	if strings.Contains(got, "\npassage_sessions_revoked_total{") {
		t.Errorf("no series should be emitted, got:\n%s", got)
	}
}

func TestWriteText_GaugeWithoutLabelsHasNoBraces(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry()
	reg.Gauge("passage_process_start_time_seconds", "Start time.", nil, constGauge(1700000000))

	got := expose(t, reg)
	if !strings.Contains(got, "passage_process_start_time_seconds 1700000000\n") {
		t.Errorf("unlabelled gauge must not use braces, got:\n%s", got)
	}
}

func TestWriteText_FormatsFloatValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value float64
		want  string
	}{
		{name: "integer", value: 5, want: "5"},
		{name: "fraction", value: 1.5, want: "1.5"},
		{name: "large", value: 1000000, want: "1000000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := newTestRegistry()
			reg.Gauge("g", "g.", nil, constGauge(tc.value))
			if got := expose(t, reg); !strings.Contains(got, "g "+tc.want+"\n") {
				t.Errorf("value = %q, want line %q", got, "g "+tc.want)
			}
		})
	}
}
