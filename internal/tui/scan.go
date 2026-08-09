package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// ScanSession reports the progress of a scan. It implements [scan.Observer].
type ScanSession struct {
	*Session
}

// scanRow is one scanner's line in the display.
type scanRow struct {
	name     string
	phase    scan.Phase
	findings int
	duration time.Duration
}

// scanModel is the bubbletea model for a scan.
//
// Rows are addressed by index rather than appended as events arrive, so the
// layout is fixed from the first frame and nothing jumps as scanners finish out
// of order.
type scanModel struct {
	target  string
	rows    []scanRow
	styles  styles
	frame   int
	quit    bool
	elapsed time.Time
}

// scanEventMsg carries a domain event into the model.
type scanEventMsg scan.Event

// tickMsg advances the spinner.
type tickMsg struct{}

// doneMsg tells the model to render its final frame.
type doneMsg struct{}

// Init implements tea.Model.
func (m scanModel) Init() tea.Cmd { return tick() }

// tick schedules the next spinner frame.
func tick() tea.Cmd {
	return tea.Tick(tickInterval, func(time.Time) tea.Msg { return tickMsg{} })
}

// Update implements tea.Model.
func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		if m.quit {
			return m, nil
		}
		m.frame++
		return m, tick()

	case scanEventMsg:
		m.apply(scan.Event(msg))
		return m, nil

	case doneMsg:
		m.quit = true
		return m, tea.Quit
	}
	return m, nil
}

// apply folds an event into the model's rows.
func (m *scanModel) apply(e scan.Event) {
	// Grow on demand: Usable emits skipped events indexed against the full
	// registry, which may be longer than the usable set Run later reports on.
	for len(m.rows) <= e.Index {
		m.rows = append(m.rows, scanRow{})
	}

	row := &m.rows[e.Index]
	row.name = e.Scanner
	row.phase = e.Phase

	if e.Findings > 0 {
		row.findings = e.Findings
	}
	if e.Duration > 0 {
		row.duration = e.Duration
	}
}

// View implements tea.Model.
func (m scanModel) View() string {
	var b strings.Builder

	fmt.Fprintf(&b, "\n  %s %s\n\n",
		m.styles.title.Render("Scanning"), m.styles.dim.Render(m.target))

	for _, row := range m.rows {
		if row.name == "" {
			continue
		}
		b.WriteString("  " + m.renderRow(row) + "\n")
	}

	b.WriteString("\n" + m.renderFooter() + "\n")
	return b.String()
}

// renderRow renders one scanner's line.
func (m scanModel) renderRow(row scanRow) string {
	mark, style, status := m.rowState(row)

	return fmt.Sprintf("%s %s %s",
		style.Render(mark),
		m.styles.name.Render(pad(row.name)),
		style.Render(status),
	)
}

// rowState maps a phase onto its marker, style, and status text.
//
// The status is always words, never color alone: this has to stay legible when
// piped, when the terminal has no color, and to anyone who cannot distinguish
// red from green.
func (m scanModel) rowState(row scanRow) (mark string, style lipglossStyle, status string) {
	switch row.phase {
	case scan.PhaseDone:
		status = fmt.Sprintf("%d finding%s", row.findings, plural(row.findings))
		if d := humanDuration(row.duration); d != "" {
			status += "   " + d
		}
		return markDone, m.styles.done, status

	case scan.PhaseFailed:
		return markFailed, m.styles.failed, "failed"

	case scan.PhaseSkipped:
		return markSkipped, m.styles.skipped, "not installed — run `pindrop setup`"

	case scan.PhaseRunning:
		return spinnerFrames[m.frame%len(spinnerFrames)], m.styles.running, "scanning…"

	case scan.PhaseQueued:
		return markPending, m.styles.dim, "waiting"

	default:
		return markPending, m.styles.dim, ""
	}
}

// lipglossStyle names the style type without importing lipgloss into every
// signature that mentions one.
type lipglossStyle = interface{ Render(...string) string }

// tally counts rows by outcome.
type tally struct {
	done, pending, failed, skipped, findings int
}

// count summarizes the rows.
//
// Skipped scanners are counted apart from the rest and excluded from the
// denominator: "2/3 scanners" should mean two of the three that can actually run,
// not two of four where the fourth was never going to.
func (m scanModel) count() tally {
	var t tally
	for _, row := range m.rows {
		if row.name == "" {
			continue
		}
		switch row.phase {
		case scan.PhaseDone:
			t.done++
			t.findings += row.findings
		case scan.PhaseRunning, scan.PhaseQueued:
			t.pending++
		case scan.PhaseFailed:
			t.failed++
		case scan.PhaseSkipped:
			t.skipped++
		}
	}
	return t
}

// renderFooter summarizes the run so far.
//
// It says "raw findings" on purpose: this is the sum of what each scanner
// reported, before cross-tool dedup, so it is legitimately larger than the number
// the report finally shows. Calling it "findings" would make the table look like
// it had lost some.
func (m scanModel) renderFooter() string {
	t := m.count()

	total := t.done + t.pending + t.failed
	summary := fmt.Sprintf("  %d/%d scanners · %d raw finding%s",
		t.done, total, t.findings, plural(t.findings))
	if t.failed > 0 {
		summary += fmt.Sprintf(" · %d failed", t.failed)
	}
	if t.skipped > 0 {
		summary += fmt.Sprintf(" · %d not installed", t.skipped)
	}

	return m.styles.dim.Render(summary)
}

// nameWidth is the column a scanner's name occupies. Wide enough for the longest
// current name ("osv-scanner") plus room for one more.
const nameWidth = 13

// pad right-pads s to [nameWidth], leaving a longer value untouched rather than
// truncating a scanner's name.
func pad(s string) string {
	if len(s) >= nameWidth {
		return s
	}
	return s + strings.Repeat(" ", nameWidth-len(s))
}

// StartScan begins reporting a scan of target.
//
// The returned session implements [scan.Observer], so it is passed straight to
// scan.Usable and scan.Run via scan.WithObserver.
func StartScan(target string, opts Options) *ScanSession {
	model := scanModel{
		target:  target,
		styles:  newStyles(opts.Color),
		elapsed: time.Now(),
	}

	session := start(opts, model)
	s := &ScanSession{Session: session}

	if opts.Mode == ModePlain {
		s.printfPlain("Scanning %s\n", target)
	}
	return s
}

// Observe implements [scan.Observer].
func (s *ScanSession) Observe(e scan.Event) {
	s.send(scanEventMsg(e))

	// Plain mode reports terminal transitions only. A CI log gains one line per
	// scanner rather than one per event.
	switch e.Phase {
	// Queued and running are deliberately silent here: plain mode reports
	// transitions a log reader cares about, not every state change.
	case scan.PhaseQueued, scan.PhaseRunning:

	case scan.PhaseDone:
		if s.firstPlain(e.Scanner) {
			s.printfPlain("  %s %s %d finding%s   %s\n", markDone, pad(e.Scanner),
				e.Findings, plural(e.Findings), humanDuration(e.Duration))
		}
	case scan.PhaseFailed:
		if s.firstPlain(e.Scanner) {
			s.printfPlain("  %s %s failed\n", markFailed, pad(e.Scanner))
		}
	case scan.PhaseSkipped:
		if s.firstPlain(e.Scanner) {
			s.printfPlain("  %s %s not installed\n", markSkipped, pad(e.Scanner))
		}
	}
}

// Stop finishes the display. It must be called before anything is written to
// stdout, so the last frame cannot interleave with the report.
func (s *ScanSession) Stop() {
	s.send(doneMsg{})
	s.Session.Stop()
	// Separate the final frame from the report that follows it on stdout. Without
	// this the table's header butts directly against the progress footer and the
	// two read as one block.
	s.separate()
}
