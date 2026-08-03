package scan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
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
func Run(ctx context.Context, scanners []Scanner, target Target) ([]Result, error) {
	results := make([]Result, len(scanners))
	errs := make([]error, len(scanners))

	var wg sync.WaitGroup
	for i, s := range scanners {
		wg.Go(func() {
			res, err := s.Scan(ctx, target)
			if err != nil {
				errs[i] = fmt.Errorf("%s: %w", s.Name(), err)
				return
			}
			results[i] = res
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

// Findings flattens results into a single slice sorted for presentation: most
// severe first, then by path, then by line, then by rule. The ordering is total
// and deterministic, so identical scans render identically.
func Findings(results []Result) []Finding {
	var all []Finding
	for _, r := range results {
		all = append(all, r.Findings...)
	}

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
