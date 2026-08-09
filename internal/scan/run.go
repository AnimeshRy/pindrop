package scan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Run executes every scanner against target concurrently and returns their
// results ordered to match scanners.
//
// One scanner failing does not discard the others: Run always returns every
// result it managed to collect, alongside a joined error describing the
// failures. Callers should render the findings they got and report the errors,
// rather than treating a partial scan as no scan.
//
// Run returns early only if ctx is cancelled, which cancels the scanners too.
//
// Pass [WithObserver] to receive progress [Event] values as scanners start and
// finish. Every scanner emits exactly one terminal event.
func Run(ctx context.Context, scanners []Scanner, target Target, opts ...RunOption) ([]Result, error) {
	cfg := newRunConfig(opts)

	results := make([]Result, len(scanners))
	errs := make([]error, len(scanners))

	// Announce the whole set before starting any of it, so a renderer can draw
	// every row on its first frame instead of growing the list as goroutines are
	// scheduled — which would make the display jump.
	for i, s := range scanners {
		cfg.notify(Event{Scanner: s.Name(), Index: i, Phase: PhaseQueued})
	}

	var wg sync.WaitGroup
	for i, s := range scanners {
		wg.Go(func() {
			cfg.notify(Event{Scanner: s.Name(), Index: i, Phase: PhaseRunning})
			started := time.Now()

			res, err := s.Scan(ctx, target)
			if err != nil {
				errs[i] = fmt.Errorf("%s: %w", s.Name(), err)
				cfg.notify(Event{
					Scanner: s.Name(), Index: i, Phase: PhaseFailed,
					Duration: time.Since(started), Err: err,
				})
				return
			}

			results[i] = res
			cfg.notify(Event{
				Scanner: s.Name(), Index: i, Phase: PhaseDone,
				Findings: len(res.Findings), Duration: res.Duration,
			})
		})
	}
	wg.Wait()

	// Drop the zero-valued slots left by scanners that failed.
	collected := results[:0]
	for i, res := range results {
		if errs[i] == nil {
			collected = append(collected, res)
		}
	}

	return collected, errors.Join(errs...)
}

// Preflight checks every scanner and returns a joined error naming each one
// that cannot run. Use it before [Run] so that a missing tool is reported as
// actionable setup guidance rather than as a scan failure.
func Preflight(ctx context.Context, scanners []Scanner) error {
	errs := make([]error, len(scanners))

	var wg sync.WaitGroup
	for i, s := range scanners {
		wg.Go(func() {
			errs[i] = s.Preflight(ctx)
		})
	}
	wg.Wait()

	return errors.Join(errs...)
}

// Usable partitions scanners into those that can run and a joined error
// describing those that cannot.
//
// Pass [WithObserver] to receive a [PhaseSkipped] event per unavailable scanner,
// so a renderer can show it as a dimmed row rather than leaving the user to
// reconcile a block of text above the display with the rows below it.
//
// This exists because "one of several scanners is not installed" is not the same
// failure as "no scanner is installed". Pindrop's first run has to work with
// nothing set up beyond a single tool, so an optional second scanner going
// missing must degrade coverage rather than abort the scan. The caller decides
// what to do with the skipped set — normally warn — and only an empty usable
// slice is fatal.
//
// The returned scanners keep their original relative order.
func Usable(ctx context.Context, scanners []Scanner, opts ...RunOption) ([]Scanner, error) {
	cfg := newRunConfig(opts)
	errs := make([]error, len(scanners))

	var wg sync.WaitGroup
	for i, s := range scanners {
		wg.Go(func() {
			errs[i] = s.Preflight(ctx)
		})
	}
	wg.Wait()

	usable := make([]Scanner, 0, len(scanners))
	for i, s := range scanners {
		if errs[i] != nil {
			cfg.notify(Event{
				Scanner: s.Name(), Index: i, Phase: PhaseSkipped, Err: errs[i],
			})
			continue
		}
		usable = append(usable, s)
	}

	return usable, errors.Join(errs...)
}

// Findings flattens results into a single slice, merges cross-tool duplicates,
// and sorts for presentation: most severe first, then by path, then by line, then
// by rule. The ordering is total and deterministic, so identical scans render
// identically.
//
// Deduplication happens here rather than in the callers because a flat list of
// every scanner's raw output is never the right thing to show a user — two tools
// reporting one vulnerability is one issue. See [Dedup].
func Findings(results []Result) []Finding {
	var all []Finding
	for _, r := range results {
		all = append(all, r.Findings...)
	}

	all = Dedup(all)

	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		switch {
		case a.Severity != b.Severity:
			return a.Severity.Rank() > b.Severity.Rank()
		case a.Location.Path != b.Location.Path:
			return a.Location.Path < b.Location.Path
		case a.Location.StartLine != b.Location.StartLine:
			return a.Location.StartLine < b.Location.StartLine
		default:
			return a.RuleID < b.RuleID
		}
	})

	return all
}
