package scan

import "time"

// Phase is where a scanner has got to in a run.
type Phase string

// The phases a scanner passes through. Each scanner emits [PhaseQueued], then
// [PhaseRunning], then exactly one of [PhaseDone] or [PhaseFailed] — or, if it
// never becomes runnable, [PhaseSkipped] from [Usable] instead.
const (
	// PhaseQueued means the scanner is about to start.
	PhaseQueued Phase = "queued"
	// PhaseRunning means its subprocess is underway.
	PhaseRunning Phase = "running"
	// PhaseDone means it finished and reported findings.
	PhaseDone Phase = "done"
	// PhaseFailed means the tool itself failed.
	PhaseFailed Phase = "failed"
	// PhaseSkipped means the scanner is unavailable and will not run. It is
	// emitted by [Usable], not [Run].
	PhaseSkipped Phase = "skipped"
)

// An Event reports one scanner's progress.
//
// It carries no presentation concept — no colors, no preformatted strings, no
// ordering guarantee across scanners. A renderer decides all of that; this is the
// domain reporting facts about itself.
type Event struct {
	// Scanner is the reporting scanner's [Scanner.Name].
	Scanner string
	// Index is its position in the slice passed to Run, stable for the whole
	// run, so a renderer can hold a fixed row per scanner rather than reordering
	// as results arrive.
	Index int
	Phase Phase

	// Findings is how many the scanner reported. Set on [PhaseDone] only, and
	// note it is the scanner's raw count — dedup happens later, so these will not
	// sum to the number of issues finally displayed.
	Findings int
	// Duration is how long the scanner took. Set on [PhaseDone] and [PhaseFailed].
	Duration time.Duration
	// Err is why it failed. Set on [PhaseFailed] and [PhaseSkipped].
	Err error
}

// An Observer receives [Event] values as a run proceeds.
//
// Implementations must be safe for concurrent use: [Run] fans scanners out across
// goroutines and calls Observe from each of them. Per-scanner ordering is total,
// because one scanner's events all come from its own goroutine; ordering between
// scanners is unspecified.
//
// It exists so a terminal UI can report progress without internal/scan knowing
// anything about rendering. An Observer must not block — a slow renderer would
// otherwise slow the scan it is describing.
type Observer interface {
	Observe(Event)
}

// ObserverFunc adapts a function to [Observer].
type ObserverFunc func(Event)

// Observe implements [Observer].
func (f ObserverFunc) Observe(e Event) { f(e) }

// A RunOption configures [Run] or [Usable].
//
// Variadic options rather than a new parameter, so that every existing call site
// and test keeps compiling and a caller that wants no progress reporting writes
// nothing.
type RunOption func(*runConfig)

// runConfig holds resolved options.
type runConfig struct {
	observer Observer
}

// WithObserver reports progress to o. A nil observer is ignored.
func WithObserver(o Observer) RunOption {
	return func(c *runConfig) {
		if o != nil {
			c.observer = o
		}
	}
}

// newRunConfig applies opts.
func newRunConfig(opts []RunOption) runConfig {
	var c runConfig
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// notify sends e if an observer is configured. Centralizing the nil check keeps
// every emission site a single unguarded call.
func (c runConfig) notify(e Event) {
	if c.observer != nil {
		c.observer.Observe(e)
	}
}
