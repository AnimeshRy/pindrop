package opengrep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// goldenRoot is the scan root the fixture's absolute paths were rewritten to.
const goldenRoot = "/home/dev/pindrop/testdata/vulnerable-app"

func loadGolden(t *testing.T) report {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "report.json"))
	if err != nil {
		t.Fatalf("reading golden report: %v", err)
	}

	var rep report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("decoding golden report: %v", err)
	}
	return rep
}

func findByRule(findings []scan.Finding, ruleID string) (scan.Finding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return scan.Finding{}, false
}

func TestConvertGolden(t *testing.T) {
	t.Parallel()

	rep := loadGolden(t)
	findings := convert(rep, goldenRoot)

	// 14 results in the fixture, 3 of them deliberately unactionable.
	if got, want := len(findings), 11; got != want {
		t.Fatalf("convert() produced %d findings, want %d", got, want)
	}

	for _, f := range findings {
		if f.Scanner != Name {
			t.Errorf("%s: Scanner = %q, want %q", f.RuleID, f.Scanner, Name)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s: empty fingerprint; Dedup passes these through ungrouped", f.RuleID)
		}
		if f.Category != scan.CategoryCode {
			t.Errorf("%s: Category = %q, want %q", f.RuleID, f.Category, scan.CategoryCode)
		}
		if f.Severity == scan.SeverityUnknown {
			t.Errorf("%s: severity is unknown; the mapping missed a value", f.RuleID)
		}
		if f.Package != nil {
			t.Errorf("%s: Package = %+v, want nil for a location-scoped finding", f.RuleID, f.Package)
		}
		if filepath.IsAbs(f.Location.Path) {
			t.Errorf("%s: path %q is absolute; identity would depend on the checkout directory",
				f.RuleID, f.Location.Path)
		}
		if f.Location.StartLine <= 0 {
			t.Errorf("%s: StartLine = %d, want a 1-indexed line", f.RuleID, f.Location.StartLine)
		}
		// The snippet is a fingerprint input, not decoration. Without it, every hit
		// of one rule in one file collapses into a single finding.
		if strings.TrimSpace(f.Location.Snippet) == "" {
			t.Errorf("%s: empty snippet", f.RuleID)
		}
		if f.Title == "" {
			t.Errorf("%s: empty title", f.RuleID)
		}
	}
}

// TestConvertDropsUnactionable pins the three filtered classes by rule ID, so a
// weakened actionable() shows up as a named failure rather than a count drift.
func TestConvertDropsUnactionable(t *testing.T) {
	t.Parallel()

	findings := convert(loadGolden(t), goldenRoot)

	for _, ruleID := range []string{
		"derived-suppressed-rule",
		"derived-inventory-rule",
		"derived-low-confidence-rule",
	} {
		if _, ok := findByRule(findings, ruleID); ok {
			t.Errorf("%s was reported, want it dropped by actionable()", ruleID)
		}
	}
}

func TestConvertFields(t *testing.T) {
	t.Parallel()

	findings := convert(loadGolden(t), goldenRoot)

	tests := []struct {
		ruleID        string
		wantPath      string
		wantSeverity  scan.Severity
		wantStartLine int
		wantCWE       string
		wantRefPrefix string
	}{
		{
			ruleID:        "go-sql-query-from-sprintf",
			wantPath:      "src/admin.go",
			wantSeverity:  scan.SeverityHigh,
			wantStartLine: 22,
			wantCWE:       "CWE-89",
			wantRefPrefix: "https://",
		},
		{
			ruleID:        "py-flask-debug-enabled",
			wantPath:      "src/report.py",
			wantSeverity:  scan.SeverityMedium,
			wantStartLine: 61,
			wantCWE:       "CWE-489",
			wantRefPrefix: "https://",
		},
		{
			ruleID:        "js-jwt-verify-algorithm-none",
			wantPath:      "src/routes.js",
			wantSeverity:  scan.SeverityHigh,
			wantStartLine: 48,
			wantCWE:       "CWE-347",
			wantRefPrefix: "https://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			t.Parallel()

			f, ok := findByRule(findings, tt.ruleID)
			if !ok {
				t.Fatalf("%s not found in converted findings", tt.ruleID)
			}
			if got := f.Location.Path; got != tt.wantPath {
				t.Errorf("path = %q, want %q", got, tt.wantPath)
			}
			if got := f.Severity; got != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", got, tt.wantSeverity)
			}
			if got := f.Location.StartLine; got != tt.wantStartLine {
				t.Errorf("StartLine = %d, want %d", got, tt.wantStartLine)
			}
			if !strings.Contains(f.Message, tt.wantCWE) {
				t.Errorf("message does not carry %s:\n%s", tt.wantCWE, f.Message)
			}
			if len(f.References) == 0 {
				t.Fatal("no references")
			}
			if !strings.HasPrefix(f.References[0], tt.wantRefPrefix) {
				t.Errorf("reference %q does not start with %q", f.References[0], tt.wantRefPrefix)
			}
			// Aliases are deliberately empty: no shared namespace exists across
			// SAST engines to canonicalize a rule ID onto. See ADR 0006.
			if len(f.Aliases) != 0 {
				t.Errorf("Aliases = %v, want none", f.Aliases)
			}
		})
	}
}

// TestRepeatedRuleStaysDistinct is the assertion that catches a dropped
// extra.lines. The fixture trips js-eval-user-input twice in one file; because
// identity for a code finding is rule ID + path + normalized snippet, dropping
// the snippet would silently merge them into one.
func TestRepeatedRuleStaysDistinct(t *testing.T) {
	t.Parallel()

	findings := convert(loadGolden(t), goldenRoot)

	var matches []scan.Finding
	for _, f := range findings {
		if f.RuleID == "js-eval-user-input" {
			matches = append(matches, f)
		}
	}

	if got, want := len(matches), 2; got != want {
		t.Fatalf("js-eval-user-input produced %d findings, want %d", got, want)
	}
	if matches[0].Fingerprint == matches[1].Fingerprint {
		t.Errorf("both hits share fingerprint %s; the snippet is not reaching identity",
			matches[0].Fingerprint)
	}
	if got := scan.Dedup(matches); len(got) != 2 {
		t.Errorf("Dedup merged them into %d finding(s), want 2", len(got))
	}
}

// TestFingerprintSurvivesReindentation is the product test in miniature: a
// formatter run must not change a finding's identity, because a triage decision
// has to be permanent.
func TestFingerprintSurvivesReindentation(t *testing.T) {
	t.Parallel()

	base := result{
		CheckID: "js-eval-user-input",
		Path:    filepath.Join(goldenRoot, "src/routes.js"),
		Start:   position{Line: 12},
		End:     position{Line: 12},
		Extra: extra{
			Message:  "eval on user input",
			Severity: "ERROR",
			Lines:    "  const result = eval(req.query.expression);",
		},
	}

	reindented := base
	reindented.Extra.Lines = "\t\tconst result  =  eval(req.query.expression);"
	// A line inserted above shifts every line number below it.
	reindented.Start.Line = 40
	reindented.End.Line = 40

	before := convert(report{Results: []result{base}}, goldenRoot)
	after := convert(report{Results: []result{reindented}}, goldenRoot)

	if before[0].Fingerprint != after[0].Fingerprint {
		t.Errorf("fingerprint changed after reindentation and a line shift:\n before %s\n  after %s",
			before[0].Fingerprint, after[0].Fingerprint)
	}
}

func TestSeverityMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  scan.Severity
	}{
		{"CRITICAL", scan.SeverityCritical},
		// The original three-value vocabulary.
		{"ERROR", scan.SeverityHigh},
		{"WARNING", scan.SeverityMedium},
		{"INFO", scan.SeverityInfo},
		// The vocabulary added upstream in 1.72; both are valid in a rule today.
		{"HIGH", scan.SeverityHigh},
		{"MEDIUM", scan.SeverityMedium},
		{"LOW", scan.SeverityLow},
		{"error", scan.SeverityHigh},
		{"  ERROR  ", scan.SeverityHigh},
		{"", scan.SeverityUnknown},
		{"EXPERIMENT", scan.SeverityUnknown},
		{"nonsense", scan.SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()
			if got := severity(tt.value); got != tt.want {
				t.Errorf("severity(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestActionable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  result
		want bool
	}{
		{
			name: "plain finding",
			res:  result{Extra: extra{Severity: "ERROR"}},
			want: true,
		},
		{
			name: "no confidence declared",
			res:  result{Extra: extra{Severity: "WARNING"}},
			want: true,
		},
		{
			name: "suppressed by comment",
			res:  result{Extra: extra{Severity: "ERROR", IsIgnored: true}},
			want: false,
		},
		{
			name: "inventory severity",
			res:  result{Extra: extra{Severity: "INVENTORY"}},
			want: false,
		},
		{
			name: "experiment severity",
			res:  result{Extra: extra{Severity: "experiment"}},
			want: false,
		},
		{
			name: "low confidence",
			res:  result{Extra: extra{Severity: "ERROR", Metadata: metadata{Confidence: "LOW"}}},
			want: false,
		},
		{
			name: "high confidence",
			res:  result{Extra: extra{Severity: "ERROR", Metadata: metadata{Confidence: "HIGH"}}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := actionable(tt.res); got != tt.want {
				t.Errorf("actionable() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestTitle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  result
		want string
	}{
		{
			name: "first sentence",
			res:  result{Extra: extra{Message: "Something is wrong. Do this instead."}},
			want: "Something is wrong.",
		},
		{
			name: "folded yaml message collapses to one line",
			res:  result{Extra: extra{Message: "Something\nis wrong. Do this\ninstead."}},
			want: "Something is wrong.",
		},
		{
			name: "no sentence break",
			res:  result{Extra: extra{Message: "Something is wrong"}},
			want: "Something is wrong",
		},
		{
			name: "empty message falls back to the rule id",
			res:  result{CheckID: "js-eval-user-input", Extra: extra{Message: "  "}},
			want: "js-eval-user-input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := title(tt.res); got != tt.want {
				t.Errorf("title() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWithCWE(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		message string
		cwes    []string
		want    string
	}{
		{
			name:    "extracts the identifier from prose",
			message: "Bad.",
			cwes:    []string{"CWE-89: Improper Neutralization of Special Elements"},
			want:    "Bad.\n\nCWE-89",
		},
		{
			name:    "several, deduplicated",
			message: "Bad.",
			cwes:    []string{"CWE-89: SQLi", "CWE-89: again", "CWE-78: cmdi"},
			want:    "Bad.\n\nCWE-89, CWE-78",
		},
		{
			name:    "no cwe leaves the message alone",
			message: "Bad.",
			cwes:    nil,
			want:    "Bad.",
		},
		{
			name:    "unparseable cwe is ignored",
			message: "Bad.",
			cwes:    []string{"see the OWASP guide"},
			want:    "Bad.",
		},
		{
			name:    "empty message",
			message: "",
			cwes:    []string{"CWE-89: SQLi"},
			want:    "CWE-89",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := withCWE(tt.message, tt.cwes); got != tt.want {
				t.Errorf("withCWE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		refs []string
		want []string
	}{
		{
			name: "keeps http and https",
			refs: []string{"https://a.example", "http://b.example"},
			want: []string{"https://a.example", "http://b.example"},
		},
		{
			name: "drops blanks, duplicates, and non-urls",
			refs: []string{"https://a.example", "", "  ", "https://a.example", "CWE-89"},
			want: []string{"https://a.example"},
		},
		{
			name: "nothing usable yields nil",
			refs: []string{"see the docs"},
			want: nil,
		},
		{
			name: "empty yields nil",
			refs: nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := references(tt.refs)
			if len(got) != len(tt.want) {
				t.Fatalf("references() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("references()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestRelativePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sourcePath string
		root       string
		want       string
	}{
		{
			name:       "absolute under the root",
			sourcePath: "/home/dev/pindrop/testdata/app/src/routes.js",
			root:       "/home/dev/pindrop/testdata/app",
			want:       "src/routes.js",
		},
		{
			name:       "outside the root falls back to the cleaned path",
			sourcePath: "/etc/passwd",
			root:       "/home/dev/pindrop",
			want:       "/etc/passwd",
		},
		{
			name:       "empty stays empty",
			sourcePath: "",
			root:       "/home/dev/pindrop",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := relativePath(tt.sourcePath, tt.root); got != tt.want {
				t.Errorf("relativePath(%q, %q) = %q, want %q", tt.sourcePath, tt.root, got, tt.want)
			}
		})
	}
}

// TestRelativePathHandlesRelativeResults covers the case where the target was
// given as a relative path, which makes Opengrep echo relative result paths.
func TestRelativePathHandlesRelativeResults(t *testing.T) {
	t.Parallel()

	root := filepath.Join("testdata", "app")
	if got, want := relativePath(filepath.Join(root, "src", "routes.js"), root), "src/routes.js"; got != want {
		t.Errorf("relativePath() = %q, want %q", got, want)
	}
}

// TestConvertEmptyReport covers a run that matched no supported language, which
// is a successful empty scan and not a failure.
func TestConvertEmptyReport(t *testing.T) {
	t.Parallel()

	if got := convert(report{}, goldenRoot); len(got) != 0 {
		t.Errorf("convert(empty) = %v, want no findings", got)
	}
}
