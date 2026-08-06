package osv

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// convert flattens an OSV-Scanner report into normalized findings.
//
// root is the directory that was scanned, used to make OSV's absolute source
// paths relative.
//
// One finding is emitted per advisory rather than per group, even though
// OSV-Scanner groups aliased advisories together. Trivy reports per advisory, so
// matching that shape is what lets the two merge; collapsing groups here would
// produce one finding where Trivy produces two and leave the extra unmatched.
// [scan.Dedup] then merges whatever genuinely coincides, which keeps one
// mechanism responsible for merging instead of two.
func convert(rep report, root string) []scan.Finding {
	var findings []scan.Finding

	for _, res := range rep.Results {
		path := relativePath(res.Source.Path, root)

		for _, entry := range res.Packages {
			for _, v := range entry.Vulnerabilities {
				findings = append(findings, vulnerabilityFinding(path, entry, v))
			}
		}
	}

	for i := range findings {
		findings[i].Fingerprint = scan.Fingerprint(findings[i])
	}
	return findings
}

func vulnerabilityFinding(path string, entry packageEntry, v vulnerability) scan.Finding {
	title := strings.TrimSpace(v.Summary)
	if title == "" {
		title = v.ID + " in " + entry.Package.Name
	}

	return scan.Finding{
		Scanner:  Name,
		RuleID:   v.ID,
		Aliases:  v.Aliases,
		Category: scan.CategoryVulnerability,
		Severity: groupSeverity(entry.Groups, v.ID),
		Title:    title,
		Message:  strings.TrimSpace(v.Details),
		Location: scan.Location{Path: path},
		Package: &scan.PackageRef{
			Name:      entry.Package.Name,
			Version:   entry.Package.Version,
			Ecosystem: entry.Package.Ecosystem,
			PURL:      purl(v, entry.Package.Name),
		},
		FixedIn:    fixedVersion(v, entry.Package.Name),
		References: referenceURLs(v.References),
	}
}

// relativePath converts OSV's absolute source path into one relative to the
// scan root, matching the form Trivy reports.
//
// This is required for cross-tool identity, not just for display: the manifest
// path is a fingerprint input, so an absolute path would make a finding's
// identity depend on the checkout directory — it would change between a
// developer's machine and CI, and never merge with Trivy's relative path.
//
// If the path cannot be made relative it is returned cleaned but unchanged.
// Reporting a usable absolute path is better than reporting none, and a finding
// that fails to merge is a visible duplicate rather than a silent loss.
func relativePath(sourcePath, root string) string {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return ""
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(sourcePath))
	}

	rel, err := filepath.Rel(absRoot, sourcePath)
	if err != nil || escapesBase(rel) {
		return filepath.ToSlash(filepath.Clean(sourcePath))
	}
	return filepath.ToSlash(rel)
}

// escapesBase reports whether a relative path climbs out of the directory it was
// computed against.
//
// The test is on the first path *component*, not on the string prefix: a
// directory legitimately named "..config" starts with ".." without escaping
// anything, and treating it as an escape would leave every finding beneath it
// keyed by an absolute path.
//
// rel comes straight from [filepath.Rel], so it is still OS-separated here —
// compare against [filepath.Separator] rather than a hardcoded slash.
func escapesBase(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// groupSeverity finds the severity of the group containing id.
//
// Severity lives on the group rather than the advisory, so every advisory in a
// group shares one. An advisory in no group — which happens for license and
// other non-vulnerability findings — has no score and is left unknown rather
// than guessed at.
func groupSeverity(groups []group, id string) scan.Severity {
	for _, g := range groups {
		for _, gid := range g.IDs {
			if gid == id {
				return severity(g.MaxSeverity)
			}
		}
	}
	return scan.SeverityUnknown
}

// severity maps a CVSS base score onto Pindrop's severity vocabulary using the
// qualitative bands from the CVSS v3.1 specification.
//
// OSV-Scanner reports a numeric score where Trivy reports a word, so unlike
// every other adapter this one converts rather than looks up. The bands are the
// standard ones, which is what makes the two tools agree: on the bundled fixture
// this mapping reproduces Trivy's grading for all six shared advisories.
//
// An unparseable or absent score becomes [scan.SeverityUnknown]. A wrong severity
// is worse than an absent one, because it distorts ranking.
func severity(score string) scan.Severity {
	s, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	if err != nil {
		return scan.SeverityUnknown
	}

	switch {
	case s >= 9.0:
		return scan.SeverityCritical
	case s >= 7.0:
		return scan.SeverityHigh
	case s >= 4.0:
		return scan.SeverityMedium
	case s > 0:
		return scan.SeverityLow
	case s == 0:
		return scan.SeverityInfo
	default:
		// A negative score is not a valid CVSS value.
		return scan.SeverityUnknown
	}
}

// fixedVersion reports the earliest version of pkg that carries a fix, or "" if
// the advisory names none.
//
// Only the affected entry matching pkg is consulted: an advisory covering several
// packages carries a range per package, and taking the first fixed version found
// would report another package's fix. GIT ranges are skipped because their events
// hold commit hashes rather than versions.
func fixedVersion(v vulnerability, pkg string) string {
	for _, a := range v.Affected {
		if a.Package.Name != pkg {
			continue
		}
		for _, r := range a.Ranges {
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// purl returns the Package URL for pkg from the advisory's affected entries.
func purl(v vulnerability, pkg string) string {
	for _, a := range v.Affected {
		if a.Package.Name == pkg && a.Package.PURL != "" {
			return a.Package.PURL
		}
	}
	return ""
}

// referenceURLs extracts advisory links, putting ADVISORY-type references first
// so the most authoritative link leads. Duplicates and blanks are dropped.
func referenceURLs(refs []reference) []string {
	if len(refs) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(refs))
	out := make([]string, 0, len(refs))

	for _, wantAdvisory := range []bool{true, false} {
		for _, r := range refs {
			isAdvisory := strings.EqualFold(r.Type, "ADVISORY")
			if isAdvisory != wantAdvisory || r.URL == "" || seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			out = append(out, r.URL)
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}
