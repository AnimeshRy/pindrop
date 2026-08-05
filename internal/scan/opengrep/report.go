package opengrep

// Hand-written mirrors of Opengrep's `--json` output, transcribed from a real
// v1.26.0 run (see testdata/report.json) rather than from the schema.
//
// The schema of record is `semgrep_output_v1.atd` in opengrep/semgrep-interfaces,
// but reading it is a trap: `extra.lines`, `extra.fingerprint`, and
// `extra.metavars` carry comments saying they require being logged in, which is
// true of upstream Semgrep since 1.98 and false of Opengrep — the fork emits them
// unconditionally, and preserving that is much of why the fork exists. A struct
// written from the schema would omit `lines`, and `lines` is what makes two hits
// of one rule in one file distinguishable. This is the same failure as the Trivy
// adapter's AVDID field, in the opposite direction.
//
// Only the fields Pindrop consumes are modeled. Notably absent: `metavars`,
// `dataflow_trace` (large, and present on every taint-mode finding),
// `engine_kind`, `validation_state`, `time`, and `explanations`.

// report is the top level of `opengrep scan --json`.
type report struct {
	Version string      `json:"version"`
	Results []result    `json:"results"`
	Errors  []scanError `json:"errors"`
	Paths   paths       `json:"paths"`
}

// result is a single rule match. Opengrep calls this a cli_match.
type result struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   position `json:"start"`
	End     position `json:"end"`
	Extra   extra    `json:"extra"`
}

// position is a 1-indexed line and column with a 0-indexed byte offset.
type position struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// extra holds everything about a match that is not its location.
type extra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	// Lines is the matched source text. Load-bearing for identity, not display:
	// it becomes Location.Snippet, which is a fingerprint input for
	// location-scoped findings.
	Lines string `json:"lines"`
	Fix   string `json:"fix,omitempty"`
	// IsIgnored marks a match suppressed by a nosem/nosemgrep/noopengrep comment.
	// Opengrep reports these rather than dropping them.
	IsIgnored bool     `json:"is_ignored,omitempty"`
	Metadata  metadata `json:"metadata"`
}

// metadata is the rule's own metadata block, passed through verbatim.
//
// Everything here is optional and author-controlled: a user-supplied ruleset may
// populate none of it. Nothing in this struct may become load-bearing.
type metadata struct {
	// CWE and OWASP are arrays of prose, not identifiers — "CWE-89: Improper
	// Neutralization of ... ('SQL Injection')" — and one rule can carry several.
	// Any use of a bare number needs a regex.
	CWE        []string `json:"cwe,omitempty"`
	OWASP      []string `json:"owasp,omitempty"`
	References []string `json:"references,omitempty"`
	Category   string   `json:"category,omitempty"`
	// Confidence is LOW|MEDIUM|HIGH, a different scale from Severity and not
	// interchangeable with it.
	Confidence  string   `json:"confidence,omitempty"`
	Subcategory []string `json:"subcategory,omitempty"`
	Technology  []string `json:"technology,omitempty"`
}

// scanError is an engine-level problem: an unparseable target, a malformed rule,
// a missing config. These are never converted into findings.
type scanError struct {
	Code    int    `json:"code"`
	Level   string `json:"level"`
	Type    string `json:"type"`
	RuleID  string `json:"rule_id,omitempty"`
	Message string `json:"message,omitempty"`
	Path    string `json:"path,omitempty"`
}

// paths records what was walked. Scanned is the useful half: an empty Scanned
// with no error means the target matched no supported language, which is a
// legitimate empty scan and not a failure.
type paths struct {
	Scanned []string `json:"scanned"`
}
