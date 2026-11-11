package metrics

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// contentType is the Prometheus text exposition format, version 0.0.4. It is
// not "application/openmetrics-text": Passage emits the 0.0.4 text format, and
// declaring that exact type keeps strict scrapers happy.
const contentType = "text/plain; version=0.0.4; charset=utf-8"

// Escapers for the two places the text format allows escaping. strings.Replacer
// scans once, so replacement output is never re-escaped.
var (
	// HELP lines escape backslashes and line feeds; a double quote is literal.
	helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	// Label values additionally escape double quotes.
	labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
)

// WriteText writes every registered family in the Prometheus text exposition
// format. Families are emitted in name order and samples in label-value order,
// so two scrapes of unchanged data are byte-identical.
//
// Gauge callbacks that fail are logged and omitted; the rest of the exposition
// is still written. An error is returned only when w itself fails.
func (r *Registry) WriteText(ctx context.Context, w io.Writer) error {
	e := &encoder{w: bufio.NewWriter(w)}
	for _, fam := range r.snapshot(ctx) {
		e.writeFamily(fam)
		if e.err != nil {
			return e.err
		}
	}
	return e.w.Flush()
}

// encoder writes the exposition format, remembering the first write error so
// callers only have to check once.
type encoder struct {
	w   *bufio.Writer
	err error
}

func (e *encoder) writeString(s string) {
	if e.err != nil {
		return
	}
	_, e.err = e.w.WriteString(s)
}

func (e *encoder) writeByte(b byte) {
	if e.err != nil {
		return
	}
	e.err = e.w.WriteByte(b)
}

// writeFamily writes one family's HELP and TYPE lines followed by its samples.
func (e *encoder) writeFamily(fam familySnapshot) {
	e.writeString("# HELP ")
	e.writeString(fam.name)
	e.writeByte(' ')
	e.writeString(helpEscaper.Replace(fam.help))
	e.writeByte('\n')

	e.writeString("# TYPE ")
	e.writeString(fam.name)
	e.writeByte(' ')
	e.writeString(string(fam.kind))
	e.writeByte('\n')

	for _, sample := range fam.samples {
		e.writeString(fam.name)
		if len(fam.labelNames) > 0 {
			e.writeByte('{')
			for i, name := range fam.labelNames {
				if i > 0 {
					e.writeByte(',')
				}
				e.writeString(name)
				e.writeString(`="`)
				e.writeString(labelEscaper.Replace(sample.values[i]))
				e.writeByte('"')
			}
			e.writeByte('}')
		}
		e.writeByte(' ')
		e.writeString(sample.value)
		e.writeByte('\n')
	}
}
