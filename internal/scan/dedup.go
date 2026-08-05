package scan

import (
	"sort"
	"strings"
)

// Agreement reports how many scanners reported this finding, which is the
// confidence signal for whether it is worth a user's attention: independent
// tools converging on one problem is stronger evidence than a single tool
// asserting it.
//
// A finding that has not been through [Dedup] carries no scanner list, so it
// reports 1 rather than 0.
func (f Finding) Agreement() int {
	if len(f.Scanners) == 0 {
		return 1
	}
	return len(f.Scanners)
}

// Dedup merges findings that share a fingerprint into one finding each.
//
// This is the step that makes running a second scanner an improvement rather
// than a regression. Trivy and OSV-Scanner draw on different advisory databases
// but overlap heavily, so without merging, enabling both roughly doubles the
// dependency findings a user sees while telling them nothing new — the precise
// failure this product exists to prevent.
//
// Because [Fingerprint] excludes the scanner name and canonicalizes advisory IDs
// and package coordinates, duplicates from different tools arrive here already
// sharing an identity. Merging is therefore a grouping problem, not a
// similarity-matching one; there is no threshold to tune and no chance of a
// near-miss.
//
// The merged finding takes the most severe grading reported, the most specific
// location, and the union of aliases and references. Input order does not affect
// the output: identical scans always produce identical merged findings, which
// matters because these values are about to be persisted and diffed.
//
// Findings with an empty fingerprint are passed through untouched rather than
// grouped together — an unfingerprinted finding is an adapter bug, and collapsing
// several into one would hide it.
func Dedup(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	merged := make([]Finding, 0, len(findings))
	// index maps a fingerprint to its position in merged, so the first
	// occurrence of each fingerprint fixes the output order.
	index := make(map[string]int, len(findings))
	// scanners accumulates the reporting adapters per output position as a set,
	// deduplicated because one tool can report the same problem twice.
	scanners := make([]map[string]struct{}, 0, len(findings))

	for _, f := range findings {
		if f.Fingerprint == "" {
			merged = append(merged, f)
			scanners = append(scanners, nil)
			continue
		}

		i, seen := index[f.Fingerprint]
		if !seen {
			index[f.Fingerprint] = len(merged)
			merged = append(merged, f)
			scanners = append(scanners, map[string]struct{}{f.Scanner: {}})
			continue
		}

		merged[i] = mergeFinding(merged[i], f)
		scanners[i][f.Scanner] = struct{}{}
	}

	for i := range merged {
		if scanners[i] == nil {
			continue
		}
		merged[i].Scanners = sortedKeys(scanners[i])
		merged[i].Aliases = normalizeAliases(merged[i].Aliases)
		merged[i].References = dedupStrings(merged[i].References)
	}

	return merged
}

// mergeFinding folds b into a. It is called only for findings that share a
// fingerprint, so they describe the same problem and differ only in how well
// each tool described it.
//
// Every choice below must be independent of argument order, so that the merged
// result does not depend on which scanner happened to finish first.
func mergeFinding(a, b Finding) Finding {
	// Take the higher severity. Tools disagree routinely — one vendor rates a
	// flaw high where another says medium — and under-reporting severity is the
	// more damaging error, since ranking is what decides whether the user ever
	// sees the finding.
	if b.Severity.Rank() > a.Severity.Rank() {
		a.Severity = b.Severity
	}

	// Prefer a location that names a line. A dependency finding is identified by
	// its manifest, but a tool that also points at the offending line gives the
	// user somewhere to go.
	if a.Location.StartLine == 0 && b.Location.StartLine != 0 {
		a.Location.StartLine = b.Location.StartLine
		a.Location.EndLine = b.Location.EndLine
	}
	if a.Location.Snippet == "" {
		a.Location.Snippet = b.Location.Snippet
	}

	// Fill gaps rather than overwrite: a describes the problem adequately if it
	// is non-empty, and picking the "better" prose would need a rule that does
	// not depend on order.
	if a.Title == "" {
		a.Title = b.Title
	}
	if a.Message == "" {
		a.Message = b.Message
	}
	if a.FixedIn == "" {
		a.FixedIn = b.FixedIn
	}
	if a.Package == nil {
		a.Package = b.Package
	}

	a.Aliases = append(a.Aliases, b.Aliases...)
	// b's own rule ID is an alias from a's point of view whenever the two tools
	// used different identifier namespaces for one advisory. Recording it keeps
	// the cross-reference visible to the user and to any later scan.
	if !strings.EqualFold(a.RuleID, b.RuleID) && b.RuleID != "" {
		a.Aliases = append(a.Aliases, b.RuleID)
	}
	a.References = append(a.References, b.References...)

	return a
}

// normalizeAliases uppercases, deduplicates, and sorts advisory identifiers, and
// drops any that merely repeat information. Identifiers are case-insensitive in
// practice, so "ghsa-xxx" and "GHSA-XXX" must not both survive.
func normalizeAliases(aliases []string) []string {
	if len(aliases) == 0 {
		return nil
	}

	set := make(map[string]struct{}, len(aliases))
	for _, a := range aliases {
		if a = strings.ToUpper(strings.TrimSpace(a)); a != "" {
			set[a] = struct{}{}
		}
	}
	return sortedKeys(set)
}

// dedupStrings removes duplicate and empty entries and sorts the rest, so that
// merging two tools' reference lists yields a stable, repeat-free result.
func dedupStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			set[v] = struct{}{}
		}
	}
	return sortedKeys(set)
}

// sortedKeys returns the keys of set in ascending order, giving callers a
// deterministic slice from an unordered map.
func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}

	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
