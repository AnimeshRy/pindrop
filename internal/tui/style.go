package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// spinnerFrames is the braille cycle used while work is in flight.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// tickInterval is how often the spinner advances. Fast enough to read as motion,
// slow enough that a scan is not spending its time redrawing.
const tickInterval = 100 * time.Millisecond

// Row markers.
//
// Every state has a distinct glyph as well as a distinct color, because color is
// never the only carrier of meaning — the same rule the dashboard's severity
// badges follow, and the reason this works at all in a pipe.
const (
	markDone    = "✔"
	markFailed  = "✘"
	markSkipped = "·"
	markPending = " "
)

// styles holds the lipgloss styles for a session.
//
// Built per session rather than as package-level variables so that --no-color
// produces genuinely unstyled output rather than styles that happen to render
// empty, and so two sessions in one process cannot fight over global state.
type styles struct {
	title   lipgloss.Style
	name    lipgloss.Style
	done    lipgloss.Style
	failed  lipgloss.Style
	skipped lipgloss.Style
	running lipgloss.Style
	dim     lipgloss.Style
}

// newStyles builds the styles, honoring color.
func newStyles(color bool) styles {
	if !color {
		var plain lipgloss.Style
		return styles{
			title: plain, name: plain, done: plain,
			failed: plain, skipped: plain, running: plain, dim: plain,
		}
	}

	return styles{
		title:   lipgloss.NewStyle().Bold(true),
		name:    lipgloss.NewStyle(),
		done:    lipgloss.NewStyle().Foreground(lipgloss.Color("2")),
		failed:  lipgloss.NewStyle().Foreground(lipgloss.Color("1")),
		skipped: lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
		running: lipgloss.NewStyle().Foreground(lipgloss.Color("4")),
		dim:     lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
}

// humanDuration renders a duration at the precision a human cares about.
func humanDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Round(time.Millisecond).Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return d.Round(time.Second).String()
	}
}

// plural returns the plural suffix for n.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
