package tui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// TestResolveMode is the gate that keeps the animation out of every context where
// it would corrupt output. Each row is a way that has gone wrong for somebody.
func TestResolveMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		flag             string
		stderrIsTerminal bool
		term             string
		logLevel         string
		want             Mode
	}{
		{
			name:             "an interactive terminal animates",
			stderrIsTerminal: true, term: "xterm-256color", logLevel: "info",
			want: ModeAnimated,
		},
		{
			name:             "a redirected stderr falls back to plain",
			stderrIsTerminal: false, term: "xterm-256color", logLevel: "info",
			want: ModePlain,
		},
		{
			name:             "TERM=dumb has no cursor addressing",
			stderrIsTerminal: true, term: "dumb", logLevel: "info",
			want: ModePlain,
		},
		{
			name:             "an unset TERM falls back to plain",
			stderrIsTerminal: true, term: "", logLevel: "info",
			want: ModePlain,
		},
		{
			name:             "debug logging shares stderr, so the frame must go",
			stderrIsTerminal: true, term: "xterm-256color", logLevel: "debug",
			want: ModePlain,
		},
		{
			name:             "debug is matched case-insensitively",
			stderrIsTerminal: true, term: "xterm-256color", logLevel: "DEBUG",
			want: ModePlain,
		},
		{
			name: "an explicit flag beats every heuristic",
			flag: "animated", stderrIsTerminal: false, term: "dumb", logLevel: "debug",
			want: ModeAnimated,
		},
		{
			name: "silent is honored on a terminal",
			flag: "silent", stderrIsTerminal: true, term: "xterm-256color", logLevel: "info",
			want: ModeSilent,
		},
		{
			name: "auto is the same as no flag",
			flag: "auto", stderrIsTerminal: true, term: "xterm-256color", logLevel: "info",
			want: ModeAnimated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ResolveMode(tt.flag, tt.stderrIsTerminal, tt.term, tt.logLevel)
			if got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateMode(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"", "auto", "animated", "plain", "silent"} {
		if err := ValidateMode(ok); err != nil {
			t.Errorf("ValidateMode(%q): unexpected error %v", ok, err)
		}
	}
	if err := ValidateMode("fancy"); err == nil {
		t.Error("ValidateMode(\"fancy\"): got nil, want an error")
	}
}

// drive folds a sequence of messages into the model, as bubbletea would.
func drive(m tea.Model, msgs ...tea.Msg) tea.Model {
	for _, msg := range msgs {
		m, _ = m.Update(msg)
	}
	return m
}

func TestScanModelView(t *testing.T) {
	t.Parallel()

	base := scanModel{target: "/repo", styles: newStyles(false)}

	tests := []struct {
		name string
		msgs []tea.Msg
		want []string
		// absent must not appear.
		absent []string
	}{
		{
			name: "queued scanners are all drawn before any runs",
			msgs: []tea.Msg{
				scanEventMsg{Scanner: "trivy", Index: 0, Phase: scan.PhaseQueued},
				scanEventMsg{Scanner: "osv", Index: 1, Phase: scan.PhaseQueued},
			},
			want: []string{"trivy", "osv", "waiting", "0/2 scanners"},
		},
		{
			name: "a running scanner shows a spinner frame and words",
			msgs: []tea.Msg{
				scanEventMsg{Scanner: "trivy", Index: 0, Phase: scan.PhaseRunning},
			},
			want: []string{"trivy", "scanning…"},
		},
		{
			name: "a finished scanner reports its count and duration",
			msgs: []tea.Msg{
				scanEventMsg{Scanner: "trivy", Index: 0, Phase: scan.PhaseRunning},
				scanEventMsg{
					Scanner: "trivy", Index: 0, Phase: scan.PhaseDone,
					Findings: 8, Duration: 640 * time.Millisecond,
				},
			},
			want:   []string{markDone, "trivy", "8 findings", "640ms", "1/1 scanners"},
			absent: []string{"scanning…"},
		},
		{
			name: "one finding is not pluralized",
			msgs: []tea.Msg{
				scanEventMsg{Scanner: "osv", Index: 0, Phase: scan.PhaseDone, Findings: 1},
			},
			want:   []string{"1 finding"},
			absent: []string{"1 findings"},
		},
		{
			name: "a failed scanner is marked and counted",
			msgs: []tea.Msg{
				scanEventMsg{
					Scanner: "opengrep", Index: 0, Phase: scan.PhaseFailed,
					Err: errors.New("boom"),
				},
			},
			want: []string{markFailed, "opengrep", "failed", "1 failed"},
		},
		{
			name: "a skipped scanner points at the fix",
			msgs: []tea.Msg{
				scanEventMsg{Scanner: "trufflehog", Index: 0, Phase: scan.PhaseSkipped},
			},
			want: []string{markSkipped, "trufflehog", "pindrop setup"},
		},
		{
			name: "rows keep their index, so out-of-order arrival does not reorder them",
			msgs: []tea.Msg{
				scanEventMsg{Scanner: "trivy", Index: 0, Phase: scan.PhaseQueued},
				scanEventMsg{Scanner: "osv", Index: 1, Phase: scan.PhaseQueued},
				scanEventMsg{Scanner: "osv", Index: 1, Phase: scan.PhaseDone, Findings: 2},
			},
			want: []string{"trivy", "osv"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			view := drive(base, tt.msgs...).View()

			for _, want := range tt.want {
				if !strings.Contains(view, want) {
					t.Errorf("view is missing %q:\n%s", want, view)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(view, absent) {
					t.Errorf("view unexpectedly contains %q:\n%s", absent, view)
				}
			}
		})
	}
}

// TestScanModelRowOrderFollowsIndex pins down that a scanner finishing early does
// not jump to the top of the list.
func TestScanModelRowOrderFollowsIndex(t *testing.T) {
	t.Parallel()

	m := drive(scanModel{target: "/repo", styles: newStyles(false)},
		scanEventMsg{Scanner: "trivy", Index: 0, Phase: scan.PhaseQueued},
		scanEventMsg{Scanner: "osv", Index: 1, Phase: scan.PhaseQueued},
		scanEventMsg{Scanner: "opengrep", Index: 2, Phase: scan.PhaseQueued},
		// The last one finishes first.
		scanEventMsg{Scanner: "opengrep", Index: 2, Phase: scan.PhaseDone, Findings: 11},
	)

	view := m.View()
	trivy, osv, opengrep := strings.Index(view, "trivy"),
		strings.Index(view, "osv"), strings.Index(view, "opengrep")

	if trivy >= osv || osv >= opengrep {
		t.Errorf("rows must stay in registry order; got positions %d, %d, %d in:\n%s",
			trivy, osv, opengrep, view)
	}
}

// TestSilentSessionWritesNothing is the guarantee --progress none makes.
func TestSilentSessionWritesNothing(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	s := StartScan("/repo", Options{Out: &buf, Mode: ModeSilent})

	s.Observe(scan.Event{Scanner: "trivy", Phase: scan.PhaseQueued})
	s.Observe(scan.Event{Scanner: "trivy", Phase: scan.PhaseDone, Findings: 3})
	s.Stop()

	if buf.Len() != 0 {
		t.Errorf("got %q, want no output", buf.String())
	}
}

func TestPlainSessionReportsTransitionsOnce(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	s := StartScan("/repo", Options{Out: &buf, Mode: ModePlain})

	s.Observe(scan.Event{Scanner: "trivy", Phase: scan.PhaseQueued})
	s.Observe(scan.Event{Scanner: "trivy", Phase: scan.PhaseRunning})
	s.Observe(scan.Event{
		Scanner: "trivy", Phase: scan.PhaseDone,
		Findings: 8, Duration: 640 * time.Millisecond,
	})
	// A duplicate terminal event must not print twice.
	s.Observe(scan.Event{Scanner: "trivy", Phase: scan.PhaseDone, Findings: 8})
	s.Observe(scan.Event{Scanner: "osv", Phase: scan.PhaseSkipped})
	s.Stop()

	out := buf.String()

	for _, want := range []string{"Scanning /repo", "trivy", "8 findings", "640ms", "osv", "not installed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "8 findings"); n != 1 {
		t.Errorf("trivy reported %d times, want 1:\n%s", n, out)
	}
	// Plain mode must never move the cursor.
	if strings.Contains(out, "\x1b[") {
		t.Errorf("plain mode emitted an escape sequence:\n%q", out)
	}
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   time.Duration
		want string
	}{
		{in: 0, want: ""},
		{in: 640 * time.Millisecond, want: "640ms"},
		{in: 1500 * time.Millisecond, want: "1.5s"},
		{in: 90 * time.Second, want: "1m30s"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := humanDuration(tt.in); got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}
