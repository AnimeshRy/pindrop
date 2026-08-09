// Package scan defines Pindrop's normalized security finding model and the
// contract every scanner adapter implements.
//
// Scanners produce events; users need issues. This package holds the vocabulary
// that turns one into the other: a single [Finding] type that every tool
// normalizes into, and [Fingerprint], which gives a finding an identity stable
// enough to track across scans.
//
// Adapters live in subpackages (for example [github.com/AnimeshRy/pindrop/internal/scan/trivy])
// and depend on this package, never the reverse. Wiring happens in the CLI.
package scan

import (
	"fmt"
	"strings"
	"time"
)

// Severity is the impact level of a finding, normalized across scanners.
//
// Individual tools use their own vocabularies (Trivy says "UNKNOWN", Semgrep
// says "WARNING"); adapters are responsible for mapping onto these values.
type Severity string

// Severity levels, ordered from least to most urgent.
const (
	SeverityUnknown  Severity = "unknown"
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// rank orders severities for sorting and threshold comparisons. Unknown sorts
// lowest so it never outranks a graded finding.
var severityRank = map[Severity]int{
	SeverityUnknown:  0,
	SeverityInfo:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

// Rank returns a monotonically increasing weight for s, suitable for sorting
// and for comparing against a minimum-severity threshold. Unrecognized values
// rank as [SeverityUnknown].
func (s Severity) Rank() int {
	return severityRank[s]
}

// Valid reports whether s is a known severity level.
func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

// ParseSeverity converts a string to a [Severity], accepting any letter case.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	if !sev.Valid() {
		return SeverityUnknown, fmt.Errorf("unknown severity %q", s)
	}
	return sev, nil
}

// Category groups findings by the kind of problem they describe. It determines
// how a finding is fingerprinted, since different kinds have different notions
// of identity — see [Fingerprint].
type Category string

// Finding categories.
const (
	// CategoryVulnerability is a known CVE in a dependency (SCA).
	CategoryVulnerability Category = "vulnerability"
	// CategorySecret is a credential committed to the repository.
	CategorySecret Category = "secret"
	// CategoryMisconfiguration is an insecure infrastructure-as-code setting.
	CategoryMisconfiguration Category = "misconfiguration"
	// CategoryCode is an insecure code pattern found by static analysis (SAST).
	CategoryCode Category = "code"
	// CategoryLicense is a dependency license policy violation.
	CategoryLicense Category = "license"
)

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	switch c {
	case CategoryVulnerability, CategorySecret, CategoryMisconfiguration,
		CategoryCode, CategoryLicense:
		return true
	default:
		return false
	}
}

// Location identifies where in the scanned tree a finding occurs.
type Location struct {
	// Path is relative to the scan root, using forward slashes.
	Path string `json:"path"`

	// StartLine and EndLine are 1-indexed; zero means "not line-scoped",
	// which is normal for dependency findings that point at a manifest.
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`

	// Snippet is the offending source text, when the scanner reports it.
	// It contributes to the fingerprint for line-scoped categories, which is
	// why it is normalized rather than compared verbatim.
	Snippet string `json:"snippet,omitempty"`
}

// PackageRef identifies a dependency. It is set only for findings that are
// scoped to a package rather than to a line of first-party code.
type PackageRef struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`

	// Ecosystem is the package registry, lowercased: "npm", "pypi", "go",
	// "maven", and so on.
	Ecosystem string `json:"ecosystem,omitempty"`

	// PURL is the Package URL (https://github.com/package-url/purl-spec),
	// when the scanner provides one.
	PURL string `json:"purl,omitempty"`
}

// A Finding is one normalized security issue. Every scanner adapter converts
// its tool's native output into this shape, which is what makes findings from
// different tools comparable, dedupable, and rankable.
type Finding struct {
	// Fingerprint is the stable identity of this finding across scans.
	// It is derived, not reported by the scanner — see [Fingerprint].
	Fingerprint string `json:"fingerprint"`

	// Provenance:

	// Scanner is the adapter that produced this finding, such as "trivy".
	// It is deliberately excluded from the fingerprint so that two tools
	// reporting the same problem collapse into one issue.
	Scanner string `json:"scanner"`

	// Scanners lists every adapter that reported this finding, sorted and
	// deduplicated. [Dedup] always populates it, even for a finding only one
	// tool reported; adapters never do, so it is nil until findings are merged.
	//
	// Its length is the confidence signal the vision doc calls for: two
	// independent tools agreeing on a finding is stronger evidence than one
	// asserting it. Use [Finding.Agreement] rather than len, so unmerged
	// findings read as 1 instead of 0.
	Scanners []string `json:"scanners,omitempty"`

	// RuleID is the tool's identifier for the check that fired: a CVE ID, a
	// Semgrep check ID, a Gitleaks rule name.
	RuleID string `json:"ruleId"`

	// Aliases are other identifiers for the same advisory — typically the CVE
	// for a GHSA-primary record, or vice versa. Adapters should populate this
	// whenever their tool provides it, because it is what lets two scanners
	// using different identifier namespaces agree on one fingerprint.
	//
	// It is an input to identity via [CanonicalAdvisoryID], not a descriptive
	// field, so adding an alias a scanner did not previously report can change
	// a fingerprint.
	Aliases []string `json:"aliases,omitempty"`

	// Classification:

	Category Category `json:"category"`
	Severity Severity `json:"severity"`

	// Description:

	// Title is a short human-readable summary, suitable for a table row.
	Title string `json:"title"`
	// Message is the full explanation, which may span multiple lines.
	Message string `json:"message,omitempty"`

	// Location of the finding within the scanned tree.
	Location Location `json:"location"`

	// Package is set when the finding is scoped to a dependency rather than
	// to first-party code; nil otherwise.
	Package *PackageRef `json:"package,omitempty"`

	// Remediation and context:

	// FixedIn is the earliest version containing a fix, when known.
	FixedIn string `json:"fixedIn,omitempty"`
	// References are URLs with further detail (advisories, docs).
	References []string `json:"references,omitempty"`
}

// Target describes what to scan.
type Target struct {
	// Path is the root directory to analyze.
	Path string `json:"path"`

	// Excludes are paths not worth scanning. Adapters translate them into
	// their tool's own flags, and [Run] applies them again to the findings
	// that come back — see [Excludes.Filter] for why both are needed.
	//
	// Excludes change which findings appear in a report; they must never
	// change the identity of one that remains. Nothing here reaches
	// [Fingerprint].
	Excludes Excludes `json:"excludes,omitzero"`
}

// Result is the outcome of running a single scanner against a single target.
type Result struct {
	Scanner   string        `json:"scanner"`
	Target    Target        `json:"target"`
	StartedAt time.Time     `json:"startedAt"`
	Duration  time.Duration `json:"durationNanos"`
	Findings  []Finding     `json:"findings"`
}

// CountBySeverity tallies r's findings by severity. Severities with no
// findings are absent from the returned map.
func (r Result) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int, len(severityRank))
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}
