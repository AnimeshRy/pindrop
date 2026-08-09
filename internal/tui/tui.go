// Package tui renders live progress for long-running commands.
//
// It is the only package that imports bubbletea or lipgloss. That confinement is
// deliberate and load-bearing: those are the only dependencies in this module
// beyond cobra, and keeping their imports in one leaf means the decision can be
// reversed by deleting a directory. See
// docs/decisions/0011-bubbletea-for-progress.md.
//
// # Everything renders to stderr
//
// stdout carries the report — a table, JSON, or SARIF — and must stay safe to
// pipe into jq or redirect to a file. This is the same rule that already puts
// slog on stderr. A caller writes its results to stdout only after [Session.Stop]
// has returned, so a frame can never interleave with the report.
//
// # It degrades rather than misbehaves
//
// When stderr is not a terminal, or TERM says nothing useful, or the user asked
// for it, a Session prints plain lines instead of animating. Nothing about the
// calling code changes: the same type does both, and [ModeSilent] does neither.
package tui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

// Mode is how a [Session] reports progress.
type Mode string

// The reporting modes.
const (
	// ModeAnimated redraws a live frame. Only for an interactive terminal.
	ModeAnimated Mode = "animated"
	// ModePlain writes one line per state transition, with no cursor movement.
	ModePlain Mode = "plain"
	// ModeSilent writes nothing.
	ModeSilent Mode = "silent"
)

// Options configure a [Session].
type Options struct {
	// Out is where frames go. Defaults to os.Stderr.
	Out io.Writer
	// Mode selects animated, plain, or silent. Defaults to [ModeSilent], so a
	// zero Options is inert rather than accidentally animating.
	Mode Mode
	// Color enables styling. Independent of Mode: --no-color means no color, not
	// no animation.
	Color bool
}

// out returns the writer to render to.
func (o Options) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return os.Stderr
}

// A Session renders the progress of one command.
//
// In [ModeAnimated] it runs a bubbletea program on its own goroutine and forwards
// updates to it; in the other modes it writes directly. Callers do not branch on
// the mode — that is the point of the type.
//
// A Session is safe for concurrent use, which it must be: scan.Run reports from
// every scanner's goroutine.
type Session struct {
	opts Options

	// program is nil unless animated.
	program *tea.Program
	done    chan struct{}

	mu      sync.Mutex
	stopped bool
	// plain tracks which rows have already been printed a terminal line, so
	// plain mode reports transitions rather than repeating itself.
	plain map[string]bool
}

// start builds a Session and, when animated, launches its program.
func start(opts Options, model tea.Model) *Session {
	s := &Session{opts: opts, plain: map[string]bool{}}

	if opts.Mode != ModeAnimated {
		return s
	}

	s.program = tea.NewProgram(
		model,
		// Frames go to stderr; stdout is the report.
		tea.WithOutput(opts.out()),
		// Never read stdin. Reading it would steal keystrokes from a shell and
		// break outright when stdin is a pipe — and there is nothing to interact
		// with in a progress display anyway.
		tea.WithInput(nil),
		// cmd/pindrop already owns SIGINT through signal.NotifyContext, and
		// context.Canceled is already treated as success there. Letting bubbletea
		// install its own handler would put two things in charge of Ctrl-C.
		tea.WithoutSignalHandler(),
		// No alt screen: it would wipe scrollback and hide the report that
		// follows. This renders inline.
	)

	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		// A failed render must not take the scan down with it: the findings are
		// the product, the animation is decoration.
		_, _ = s.program.Run()
	}()

	return s
}

// send forwards a message to the program, if one is running.
func (s *Session) send(msg tea.Msg) {
	if s.program != nil {
		s.program.Send(msg)
	}
}

// Stop finishes the display and restores the terminal.
//
// It is idempotent and safe to call from a defer as well as explicitly. Callers
// should call it before writing anything to stdout, so the final frame is
// complete before the report begins.
func (s *Session) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.mu.Unlock()

	if s.program == nil {
		return
	}

	s.program.Quit()
	<-s.done

	// Restore the cursor explicitly rather than trusting teardown. If the process
	// is interrupted the moment after a frame hid it, an invisible cursor is left
	// in the user's shell — a small bug with a very annoying blast radius.
	_, _ = io.WriteString(s.opts.out(), showCursor)
}

// showCursor is the ANSI sequence that makes the cursor visible again.
const showCursor = "\x1b[?25h"

// separate writes a blank line after the display, so the report that follows does
// not butt against it. Silent mode writes nothing, as always.
func (s *Session) separate() {
	if s.opts.Mode == ModeSilent {
		return
	}
	_, _ = io.WriteString(s.opts.out(), "\n")
}

// printfPlain writes a line in plain mode.
func (s *Session) printfPlain(format string, args ...any) {
	if s.opts.Mode != ModePlain {
		return
	}
	_, _ = fmt.Fprintf(s.opts.out(), format, args...)
}

// firstPlain reports whether key has yet to produce a plain-mode line, marking it
// as seen. It keeps a CI log to one line per transition rather than one per event.
func (s *Session) firstPlain(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.plain[key] {
		return false
	}
	s.plain[key] = true
	return true
}

// ResolveMode decides how to report progress.
//
// A pure function of its inputs so the whole matrix can be tested without a
// terminal. Each rule earns its place:
//
//   - An explicit --progress value always wins.
//   - stderr not being a character device means CI, a redirect, or a pipe. Cursor
//     movement there produces escape-sequence soup in a log file.
//   - TERM=dumb or unset means the terminal has no cursor addressing to use.
//   - Debug logging goes to stderr through slog, and any concurrent writer
//     shreds a bubbletea frame. This works at all only because every adapter
//     buffers its child's stdout and stderr; the moment a human turns on debug
//     logs, the animation has to step aside.
func ResolveMode(flag string, stderrIsTerminal bool, term, logLevel string) Mode {
	if mode, ok := parseMode(flag); ok {
		return mode
	}

	switch {
	case !stderrIsTerminal:
		return ModePlain
	case term == "" || term == "dumb":
		return ModePlain
	case strings.EqualFold(logLevel, "debug"):
		return ModePlain
	default:
		return ModeAnimated
	}
}

// ModeNames lists the valid --progress values, for flag help and validation.
//
// "none" is accepted alongside "silent" because it is what the flag's own help
// text says, and a flag that rejects the value it advertises is worse than one
// that accepts a synonym.
var ModeNames = []string{"auto", string(ModeAnimated), string(ModePlain), "none"}

// parseMode maps a flag value onto a Mode, reporting whether it named one.
// An empty value or "auto" names none, leaving the decision to the heuristics.
func parseMode(flag string) (Mode, bool) {
	switch flag {
	case string(ModeAnimated):
		return ModeAnimated, true
	case string(ModePlain):
		return ModePlain, true
	case string(ModeSilent), "none", "off":
		return ModeSilent, true
	default:
		return "", false
	}
}

// ValidateMode rejects an unrecognized --progress value.
func ValidateMode(flag string) error {
	if _, ok := parseMode(flag); ok {
		return nil
	}
	if flag == "" || flag == "auto" {
		return nil
	}
	return fmt.Errorf("invalid --progress %q: want %s", flag, strings.Join(ModeNames, ", "))
}
