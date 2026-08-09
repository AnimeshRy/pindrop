package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// timeRounding keeps reported durations readable.
const timeRounding = 10 * time.Millisecond

// Column widths for the human-readable table. Long values are truncated rather
// than wrapped, because a scan that reflows into paragraphs is unscannable.
const (
	maxRuleWidth     = 24
	maxLocationWidth = 42
	maxSummaryWidth  = 56
)

// ANSI escape sequences, applied only when [Options.Color] is set.
const (
	ansiReset  = "\033[0m"
	ansiDim    = "\033[2m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiOrange = "\033[33m"
	ansiYellow = "\033[93m"
	ansiBlue   = "\033[34m"
	ansiGray   = "\033[90m"
)

// severityColor maps a severity to its ANSI color.
var severityColor = map[scan.Severity]string{
	scan.SeverityCritical: ansiBold + ansiRed,
	scan.SeverityHigh:     ansiRed,
	scan.SeverityMedium:   ansiOrange,
	scan.SeverityLow:      ansiYellow,
	scan.SeverityInfo:     ansiBlue,
	scan.SeverityUnknown:  ansiGray,
}

// displayOrder lists severities most urgent first, for the summary line.
var displayOrder = []scan.Severity{
	scan.SeverityCritical,
	scan.SeverityHigh,
	scan.SeverityMedium,
	scan.SeverityLow,
	scan.SeverityInfo,
	scan.SeverityUnknown,
}

// errWriter accumulates the first write error so that a long sequence of
// formatted writes can be expressed without an error check on every line.
// Subsequent writes are skipped once an error has occurred.
//
// See https://go.dev/blog/errors-are-values.
type errWriter struct {
	w   io.Writer
	err error
}

// printf writes a formatted line, doing nothing if a previous write failed.
func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

// Table renders results as an aligned, severity-ordered table followed by a
// summary line.
//
// The ordering is deliberate: the whole point of the product is that a user
// reads the top of this list and stops. Findings are sorted most severe first
// by [scan.Findings].
func Table(w io.Writer, results []scan.Result, opts Options) error {
	return renderTable(w, scan.Findings(results), newScanSummaries(results), opts)
}

// renderTable is the shared body of [Table] and the table arm of
// [WriteDocument]. It takes an already-flattened finding set plus the
// per-scanner summaries, which is precisely the pair a [Document] carries, so
// results-driven and document-driven rendering run the same code.
//
// It does not sort: findings arrive severity-ordered from [scan.Findings], and
// a document built by [NewDocument] preserves that order.
func renderTable(w io.Writer, findings []scan.Finding, scans []ScanSummary, opts Options) error {
	ew := &errWriter{w: w}
	if len(findings) == 0 {
		ew.printf("%s\n", paint(opts, ansiDim, "No findings."))
		return ew.err
	}

	shown := findings
	if opts.Limit > 0 && len(findings) > opts.Limit {
		shown = findings[:opts.Limit]
	}

	if err := writeRows(w, shown, opts); err != nil {
		return err
	}

	if hidden := len(findings) - len(shown); hidden > 0 {
		ew.printf("%s\n", paint(opts, ansiDim,
			fmt.Sprintf("  ... and %d more (use --limit 0 to show all)", hidden)))
	}

	writeSummary(ew, scans, findings, opts)
	return ew.err
}

// writeRows renders the aligned finding table through a tabwriter.
func writeRows(w io.Writer, findings []scan.Finding, opts Options) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	ew := &errWriter{w: tw}

	header := []string{"SEVERITY", "CATEGORY", "RULE", "LOCATION", "SUMMARY"}
	ew.printf("%s\n", paint(opts, ansiDim, strings.Join(header, "\t")))

	for _, f := range findings {
		ew.printf("%s\t%s\t%s\t%s\t%s\n",
			paint(opts, severityColor[f.Severity], strings.ToUpper(string(f.Severity))),
			f.Category,
			truncate(f.RuleID, maxRuleWidth),
			truncate(location(f), maxLocationWidth),
			truncate(summary(f), maxSummaryWidth),
		)
	}

	if ew.err != nil {
		return fmt.Errorf("writing table rows: %w", ew.err)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing table: %w", err)
	}
	return nil
}

// writeSummary prints the trailing counts and timing lines.
func writeSummary(ew *errWriter, scans []ScanSummary, findings []scan.Finding, opts Options) {
	counts := make(map[scan.Severity]int, len(displayOrder))
	for _, f := range findings {
		counts[f.Severity]++
	}

	parts := make([]string, 0, len(displayOrder))
	for _, sev := range displayOrder {
		if n := counts[sev]; n > 0 {
			parts = append(parts, paint(opts, severityColor[sev], fmt.Sprintf("%d %s", n, sev)))
		}
	}

	ew.printf("\n%s  %s\n",
		paint(opts, ansiBold, fmt.Sprintf("%d findings", len(findings))),
		strings.Join(parts, "  "),
	)

	for _, s := range scans {
		d := time.Duration(s.DurationMS) * time.Millisecond
		ew.printf("%s\n", paint(opts, ansiDim, fmt.Sprintf("  %s scanned %s in %s",
			s.Scanner, s.Target, d.Round(timeRounding))))
	}
}

// location renders a finding's path, appending the line when it has one.
func location(f scan.Finding) string {
	if f.Location.StartLine > 0 {
		return fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine)
	}
	return f.Location.Path
}

// summary picks the most informative single line available for a finding.
func summary(f scan.Finding) string {
	if f.Title != "" {
		return firstLine(f.Title)
	}
	if f.Message != "" {
		return firstLine(f.Message)
	}
	return f.RuleID
}

// firstLine returns s up to its first newline, with surrounding space removed.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// truncate shortens s to at most width runes, marking elision with an ellipsis.
// It counts runes rather than bytes so that multibyte text does not overflow
// the column.
func truncate(s string, width int) string {
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width <= 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}

// paint wraps s in an ANSI color when coloring is enabled.
func paint(opts Options, color, s string) string {
	if !opts.Color || color == "" {
		return s
	}
	return color + s + ansiReset
}
