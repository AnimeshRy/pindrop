package scan

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recorder is a concurrency-safe Observer for tests. The mutex is the point:
// running these under -race is what actually asserts the contract that Observe
// may be called from every scanner's goroutine.
type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) Observe(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// phasesFor returns the phases recorded for one scanner, in order.
func (r *recorder) phasesFor(name string) []Phase {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []Phase
	for _, e := range r.events {
		if e.Scanner == name {
			out = append(out, e.Phase)
		}
	}
	return out
}

// find returns the first recorded event for a scanner in a given phase.
func (r *recorder) find(name string, phase Phase) (Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, e := range r.events {
		if e.Scanner == name && e.Phase == phase {
			return e, true
		}
	}
	return Event{}, false
}

// fakeScanner is a Scanner with controllable behavior.
type fakeScanner struct {
	name      string
	findings  int
	delay     time.Duration
	scanErr   error
	preflight error
}

func (f *fakeScanner) Name() string                    { return f.name }
func (f *fakeScanner) Preflight(context.Context) error { return f.preflight }

func (f *fakeScanner) Scan(ctx context.Context, target Target) (Result, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}
	if f.scanErr != nil {
		return Result{}, f.scanErr
	}

	return Result{
		Scanner:  f.name,
		Target:   target,
		Duration: f.delay,
		Findings: make([]Finding, f.findings),
	}, nil
}

func TestRunEmitsOneTerminalEventPerScanner(t *testing.T) {
	t.Parallel()

	boom := errors.New("the tool crashed")
	scanners := []Scanner{
		&fakeScanner{name: "alpha", findings: 3, delay: 20 * time.Millisecond},
		&fakeScanner{name: "beta", scanErr: boom},
		&fakeScanner{name: "gamma", findings: 1},
	}

	rec := &recorder{}
	results, err := Run(context.Background(), scanners, Target{Path: "."}, WithObserver(rec))

	// The pre-existing contract must be untouched by the observer.
	if len(results) != 2 {
		t.Errorf("results: got = %d, want 2 (a failure must not discard the others)", len(results))
	}
	if !errors.Is(err, boom) {
		t.Errorf("error: got = %v, want it to wrap %v", err, boom)
	}

	tests := []struct {
		scanner string
		want    []Phase
	}{
		{scanner: "alpha", want: []Phase{PhaseQueued, PhaseRunning, PhaseDone}},
		{scanner: "beta", want: []Phase{PhaseQueued, PhaseRunning, PhaseFailed}},
		{scanner: "gamma", want: []Phase{PhaseQueued, PhaseRunning, PhaseDone}},
	}

	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			got := rec.phasesFor(tt.scanner)
			if len(got) != len(tt.want) {
				t.Fatalf("phases: got = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("phase %d: got = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}

	// A renderer holds a row per index, so the index must match the input order.
	for i, name := range []string{"alpha", "beta", "gamma"} {
		e, ok := rec.find(name, PhaseQueued)
		if !ok {
			t.Fatalf("%s never reported queued", name)
		}
		if e.Index != i {
			t.Errorf("%s index: got = %d, want %d", name, e.Index, i)
		}
	}

	if e, _ := rec.find("alpha", PhaseDone); e.Findings != 3 {
		t.Errorf("alpha findings: got = %d, want 3", e.Findings)
	}
	if e, _ := rec.find("beta", PhaseFailed); !errors.Is(e.Err, boom) {
		t.Errorf("beta error: got = %v, want it to wrap %v", e.Err, boom)
	}
}

// TestRunQueuesEverythingBeforeStarting pins down the property a stable display
// depends on: every row is known before any scanner runs, so the list cannot grow
// underneath the user.
func TestRunQueuesEverythingBeforeStarting(t *testing.T) {
	t.Parallel()

	scanners := []Scanner{
		&fakeScanner{name: "alpha", delay: 30 * time.Millisecond},
		&fakeScanner{name: "beta"},
		&fakeScanner{name: "gamma"},
	}

	rec := &recorder{}
	if _, err := Run(context.Background(), scanners, Target{Path: "."}, WithObserver(rec)); err != nil {
		t.Fatalf("Run: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()

	for i, e := range rec.events[:len(scanners)] {
		if e.Phase != PhaseQueued {
			t.Fatalf("event %d: got phase %q, want every scanner queued first (%v)",
				i, e.Phase, rec.events)
		}
	}
}

func TestRunWithoutAnObserverIsUnchanged(t *testing.T) {
	t.Parallel()

	scanners := []Scanner{&fakeScanner{name: "alpha", findings: 2}}

	// No option at all, and an explicitly nil observer, must both be safe.
	for _, opts := range [][]RunOption{nil, {WithObserver(nil)}} {
		results, err := Run(context.Background(), scanners, Target{Path: "."}, opts...)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(results) != 1 || len(results[0].Findings) != 2 {
			t.Errorf("results: got = %+v, want one result with 2 findings", results)
		}
	}
}

func TestUsableEmitsSkipped(t *testing.T) {
	t.Parallel()

	missing := &UnavailableError{Scanner: "beta", Reason: "not installed"}
	scanners := []Scanner{
		&fakeScanner{name: "alpha"},
		&fakeScanner{name: "beta", preflight: missing},
		&fakeScanner{name: "gamma"},
	}

	rec := &recorder{}
	usable, err := Usable(context.Background(), scanners, WithObserver(rec))

	if len(usable) != 2 {
		t.Errorf("usable: got = %d, want 2", len(usable))
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("error: got = %v, want it to wrap ErrUnavailable", err)
	}

	if phases := rec.phasesFor("beta"); len(phases) != 1 || phases[0] != PhaseSkipped {
		t.Errorf("beta phases: got = %v, want [skipped]", phases)
	}
	// An available scanner must stay silent here; it reports through Run instead.
	for _, name := range []string{"alpha", "gamma"} {
		if phases := rec.phasesFor(name); len(phases) != 0 {
			t.Errorf("%s phases: got = %v, want none from Usable", name, phases)
		}
	}

	if e, ok := rec.find("beta", PhaseSkipped); !ok || !errors.Is(e.Err, ErrUnavailable) {
		t.Errorf("skipped event must carry the reason; got = %+v", e)
	}
}

func TestObserverFuncAdaptsAFunction(t *testing.T) {
	t.Parallel()

	var count int
	var mu sync.Mutex

	obs := ObserverFunc(func(Event) {
		mu.Lock()
		defer mu.Unlock()
		count++
	})

	scanners := []Scanner{&fakeScanner{name: "alpha"}}
	if _, err := Run(context.Background(), scanners, Target{Path: "."}, WithObserver(obs)); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// queued, running, done.
	if count != 3 {
		t.Errorf("events: got = %d, want 3", count)
	}
}
