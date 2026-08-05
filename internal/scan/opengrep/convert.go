package opengrep

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// cwePattern extracts the identifier from Opengrep's prose CWE strings, which
// look like "CWE-89: Improper Neutralization of ... ('SQL Injection')".
var cwePattern = regexp.MustCompile(`CWE-\d+`)

// convert flattens an Opengrep report into normalized findings.
//
// root is the directory that was scanned, used to make Opengrep's paths relative:
// it echoes the target back in the form it was given, so an absolute target
// yields absolute result paths.
func convert(rep report, root string) []scan.Finding {
	var findings []scan.Finding

	for _, res := range rep.Results {
		if !actionable(res) {
			continue
		}
		findings = append(findings, codeFinding(res, root))
	}

	for i := range findings {
		findings[i].Fingerprint = scan.Fingerprint(findings[i])
	}
	return findings
}

func codeFinding(res result, root string) scan.Finding {
	message := strings.TrimSpace(res.Extra.Message)

	return scan.Finding{
		Scanner: Name,
		RuleID:  res.CheckID,
		// No Aliases. Opengrep reports no second identifier for a match, and
		// there is no shared namespace across SAST engines to canonicalize a rule
		// ID onto — see the package comment and ADR 0006. This is a decision, not
		// the omission scanners.md warns about.
		Category: scan.CategoryCode,
		Severity: severity(res.Extra.Severity),
		Title:    title(res),
		Message:  withCWE(message, res.Extra.Metadata.CWE),
		Location: scan.Location{
			Path:      relativePath(res.Path, root),
			StartLine: res.Start.Line,
			EndLine:   res.End.Line,
			// The matched source, and the reason two hits of one rule in one file
			// stay two findings: it is hashed into the fingerprint. Dropping it
			// would silently merge them.
			Snippet: res.Extra.Lines,
		},
		// No Package: a SAST finding is scoped to a location, not a dependency.
		FixedIn:    "",
		References: references(res.Extra.Metadata.References),
	}
}

// actionable reports whether a match is worth showing a user.
//
// Every adapter owes its output a filter — see the license-scanner discussion in
// docs/architecture/scanners.md. The bundled ruleset is curated, so this mostly
// protects the --opengrep-rules path, where a user may point at a corpus of
// hundreds of rules whose informational half would bury the actionable half.
func actionable(res result) bool {
	// The author already declared this match uninteresting with a nosemgrep or
	// noopengrep comment. Opengrep reports it rather than dropping it; honoring
	// the suppression is the whole point of the comment.
	if res.Extra.IsIgnored {
		return false
	}

	// EXPERIMENT and INVENTORY are not defect severities. They mark rules used for
	// rule development and for cataloguing what a codebase contains — an SBOM
	// question, not a security one.
	switch strings.ToUpper(strings.TrimSpace(res.Extra.Severity)) {
	case "EXPERIMENT", "INVENTORY":
		return false
	}

	// A rule that declares its own confidence as low is telling us it expects to
	// be wrong often. Absent confidence passes: most rules do not set it, and
	// dropping everything unlabeled would discard nearly any third-party ruleset.
	if strings.EqualFold(strings.TrimSpace(res.Extra.Metadata.Confidence), "LOW") {
		return false
	}

	return true
}

// severity maps Opengrep's severity vocabulary onto Pindrop's.
//
// The enum has eight values, not the three that `--severity` accepts as a filter.
// ERROR/WARNING/INFO are the original set; CRITICAL/HIGH/MEDIUM/LOW were added in
// upstream 1.72 and both are valid in a rule today. The ERROR->high and
// WARNING->medium pairings are the equivalences upstream states in its own schema
// rather than a guess of ours.
//
// Anything unrecognized becomes [scan.SeverityUnknown]. A wrong severity is worse
// than an absent one, because it distorts ranking.
func severity(value string) scan.Severity {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return scan.SeverityCritical
	case "ERROR", "HIGH":
		return scan.SeverityHigh
	case "WARNING", "MEDIUM":
		return scan.SeverityMedium
	case "LOW":
		return scan.SeverityLow
	case "INFO":
		return scan.SeverityInfo
	default:
		return scan.SeverityUnknown
	}
}

// title returns a one-line summary for a match.
//
// Opengrep has no title field — a rule carries only a message, which our own
// rules deliberately write as a full explanation ending in what to do instead. So
// the first sentence becomes the title and the whole text stays in the message.
// A rule whose message has no sentence break falls back to the rule ID, which is
// always more useful in a table than a truncated paragraph.
func title(res result) string {
	message := strings.TrimSpace(res.Extra.Message)
	if message == "" {
		return res.CheckID
	}

	// Collapse the newlines a folded YAML message arrives with, so the title is a
	// single line regardless of how the rule was formatted.
	message = strings.Join(strings.Fields(message), " ")

	if idx := strings.Index(message, ". "); idx > 0 {
		return message[:idx+1]
	}
	return message
}

// withCWE appends the CWE identifiers to a message.
//
// The finding model has no CWE field, and adding one to carry a single scanner's
// vocabulary is what docs/architecture/finding-model.md warns against. The
// identifiers are still worth surfacing, so they ride along in the message where
// every renderer already shows them.
func withCWE(message string, cwes []string) string {
	ids := make([]string, 0, len(cwes))
	seen := make(map[string]bool, len(cwes))

	for _, c := range cwes {
		id := cwePattern.FindString(c)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return message
	}
	if message == "" {
		return strings.Join(ids, ", ")
	}
	return message + "\n\n" + strings.Join(ids, ", ")
}

// references returns the rule's reference URLs, dropping blanks and duplicates.
//
// Only http references are kept. A rule's metadata is author-controlled and may
// hold anything; a renderer showing a reference expects something clickable.
func references(refs []string) []string {
	if len(refs) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(refs))
	out := make([]string, 0, len(refs))

	for _, r := range refs {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		if !strings.HasPrefix(r, "http://") && !strings.HasPrefix(r, "https://") {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// relativePath converts Opengrep's result path into one relative to the scan
// root.
//
// Required for identity, not display: the path is a fingerprint input for
// location-scoped findings, so an absolute path would make a finding's identity
// depend on the checkout directory and change between a laptop and CI.
//
// If the path cannot be made relative it is returned cleaned but unchanged.
// Reporting a usable absolute path beats reporting none.
func relativePath(sourcePath, root string) string {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return ""
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(sourcePath))
	}

	// Opengrep echoes the target path back in the form it was given, so a
	// relative target yields relative results. Those are relative to the process
	// working directory, which is what filepath.Abs assumes too.
	absSource, err := filepath.Abs(sourcePath)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(sourcePath))
	}

	rel, err := filepath.Rel(absRoot, absSource)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(filepath.Clean(sourcePath))
	}
	return filepath.ToSlash(rel)
}
