package history

import (
	"slices"
	"time"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// advance folds one run's findings into the lifecycle index and returns the new
// index, the status each fingerprint holds as of this run, and what changed.
//
// It is pure: no clock, no filesystem, no store. That is deliberate, because
// this is the function the whole feature is judged on, and it is only
// exhaustively testable while it stays that way. The store calls it once per run
// during a normal Put and once per run again when replaying history to rebuild.
//
// The transition table, where "observed" means a scanner that previously
// reported the finding ran in this run *and* the exclusion set is unchanged:
//
//	prior state           present now?    new status
//	absent                yes             new        (FirstRun = run)
//	new/open/regressed    yes             open       (Occurrences++)
//	fixed                 yes             regressed  (Regressions++)
//	new/open/regressed    no, observed    fixed      (FixedRun = run)
//	new/open/regressed    no, unobserved  unchanged
//	fixed                 no              fixed
//
// The two guards on the fixed transition are the point of the package:
//
//   - ran is the set of scanners this run actually executed. A finding is
//     concluded fixed only if that set intersects the set of scanners that have
//     reported it before. Without this, `pindrop scan --scanners vuln` marks
//     every secret and code finding fixed, because they are absent for want of
//     a scanner rather than for want of a bug. Intersection, not containment: a
//     finding two tools reported and one tool re-checked is treated as checked,
//     which trades a rare premature "fixed" — corrected to "regressed" on the
//     next full scan — against never closing anything after a tool is dropped.
//   - scopeChanged says the effective exclusion set differs from the previous
//     run's. Findings that vanish under a new exclusion were not fixed, they
//     were hidden, so the whole run is barred from concluding anything fixed.
//
// Findings with an empty fingerprint carry no identity and so cannot carry a
// lifecycle; they are skipped entirely rather than collapsed together under the
// empty key. An unfingerprinted finding is an adapter bug, and merging a run's
// worth of them into one state entry would hide it. They still appear in the
// run's stored document.
//
// Neither the returned index nor prev is aliased: prev is copied, so a caller
// whose write fails afterwards still holds the index it started with.
func advance(prev map[string]FindingState, cur []scan.Finding, ran map[string]bool,
	scopeChanged bool, run RunID, at time.Time,
) (next map[string]FindingState, statuses map[string]scan.Status, delta DeltaCounts) {
	next = make(map[string]FindingState, len(prev)+len(cur))
	for fp, st := range prev {
		next[fp] = st.clone()
	}
	statuses = make(map[string]scan.Status, len(cur))

	present := make(map[string]bool, len(cur))
	for _, f := range cur {
		fp := f.Fingerprint
		if fp == "" {
			continue
		}
		if present[fp] {
			// A repeated fingerprint within one run is one finding reported
			// twice; only its scanner set is new information.
			st := next[fp]
			st.Scanners = mergeScanners(st.Scanners, f)
			next[fp] = st
			continue
		}
		present[fp] = true

		st, existed := next[fp]
		switch {
		case !existed:
			st = FindingState{
				Fingerprint: fp,
				Status:      scan.StatusNew,
				FirstSeenAt: at,
				FirstRun:    run,
			}
			delta.New++
		case st.Status == scan.StatusFixed:
			st.Status = scan.StatusRegressed
			st.Regressions++
			delta.Regressed++
		default:
			st.Status = scan.StatusOpen
			delta.StillOpen++
		}

		st.Occurrences++
		st.LastSeenAt = at
		st.LastRun = run
		// The freshest report wins for display fields: a severity re-rated by an
		// advisory update should show the new rating, and none of these are
		// fingerprint inputs, so none of them can change identity.
		st.Severity = f.Severity
		st.Category = f.Category
		st.Title = f.Title
		st.Scanners = mergeScanners(st.Scanners, f)

		next[fp] = st
		statuses[fp] = st.Status
	}

	for fp, st := range next {
		if present[fp] || st.Status == scan.StatusFixed {
			continue
		}
		if scopeChanged || !checkedBy(st.Scanners, ran) {
			// Not observed. Leaving the prior status untouched is the entire
			// difference between "we looked and it is gone" and "we did not
			// look", and only the first one is worth telling a user about.
			continue
		}
		st.Status = scan.StatusFixed
		st.FixedAt = at
		st.FixedRun = run
		next[fp] = st
		statuses[fp] = st.Status
		delta.Fixed++
	}

	return next, statuses, delta
}

// checkedBy reports whether any scanner that has previously reported a finding
// ran in this run. An empty ran set — a run that recorded no scanners at all —
// can conclude nothing, which is the safe direction.
func checkedBy(reporters []string, ran map[string]bool) bool {
	for _, s := range reporters {
		if ran[s] {
			return true
		}
	}
	return false
}

// mergeScanners returns the union of prior and the scanners named by f, sorted
// and deduplicated.
//
// Both [scan.Finding.Scanner] and [scan.Finding.Scanners] are read because the
// second is populated only once findings have been merged by [scan.Dedup]; an
// adapter's own output carries the first alone.
func mergeScanners(prior []string, f scan.Finding) []string {
	merged := prior
	add := func(name string) {
		if name == "" || slices.Contains(merged, name) {
			return
		}
		merged = append(merged, name)
	}
	add(f.Scanner)
	for _, s := range f.Scanners {
		add(s)
	}
	if len(merged) > len(prior) {
		// Copy before sorting so a state we did not otherwise touch is not
		// reordered underneath a caller holding it.
		merged = slices.Clone(merged)
		slices.Sort(merged)
	}
	return merged
}

// scannersThatRan projects a run's scan summaries into the set rule 1 needs.
func scannersThatRan(scans []report.ScanSummary) map[string]bool {
	ran := make(map[string]bool, len(scans))
	for _, s := range scans {
		if s.Scanner != "" {
			ran[s.Scanner] = true
		}
	}
	return ran
}

// countFindings tallies findings for a run summary. Repeated fingerprints are
// counted once, matching what the lifecycle index records.
func countFindings(findings []scan.Finding) Counts {
	counts := Counts{
		BySeverity: map[scan.Severity]int{},
		ByCategory: map[scan.Category]int{},
	}
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		if f.Fingerprint != "" {
			if seen[f.Fingerprint] {
				continue
			}
			seen[f.Fingerprint] = true
		}
		counts.Total++
		counts.BySeverity[f.Severity]++
		counts.ByCategory[f.Category]++
	}
	return counts.compact()
}

// countOpen tallies the findings currently in an open state. It reads the
// lifecycle index rather than the newest run's findings, because those two
// disagree whenever a run was scoped to a subset of scanners — and the index is
// the one that still knows about the secrets nobody scanned for this time.
func countOpen(states map[string]FindingState) Counts {
	counts := Counts{
		BySeverity: map[scan.Severity]int{},
		ByCategory: map[scan.Category]int{},
	}
	for _, st := range states {
		if !st.Status.Open() {
			continue
		}
		counts.Total++
		counts.BySeverity[st.Severity]++
		counts.ByCategory[st.Category]++
	}
	return counts.compact()
}

// compact drops empty breakdown maps so that a clean scan serializes as a bare
// total rather than as two empty objects.
func (c Counts) compact() Counts {
	if len(c.BySeverity) == 0 {
		c.BySeverity = nil
	}
	if len(c.ByCategory) == 0 {
		c.ByCategory = nil
	}
	return c
}
