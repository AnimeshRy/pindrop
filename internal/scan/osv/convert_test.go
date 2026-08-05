package osv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// scanRoot is the directory the golden report was captured against. Paths in the
// fixture are absolute under this prefix, as OSV-Scanner really emits them.
const scanRoot = "/home/dev/pindrop/testdata/vulnerable-app"

// loadGolden decodes the captured report.
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

// findByRule returns the finding with the given rule ID.
func findByRule(findings []scan.Finding, ruleID string) (scan.Finding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return scan.Finding{}, false
}

// TestConvertGolden checks the whole conversion against real captured output.
func TestConvertGolden(t *testing.T) {
	t.Parallel()

	findings := convert(loadGolden(t), scanRoot)

	// Six advisories in the captured lockfile result plus one synthetic Go
	// advisory. The empty requirements.txt result contributes nothing.
	if len(findings) != 7 {
		t.Fatalf("converted %d findings, want 7", len(findings))
	}

	for _, f := range findings {
		if f.Scanner != Name {
			t.Errorf("%s: Scanner = %q, want %q", f.RuleID, f.Scanner, Name)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s: empty fingerprint", f.RuleID)
		}
		if f.Category != scan.CategoryVulnerability {
			t.Errorf("%s: Category = %q", f.RuleID, f.Category)
		}
		if f.Package == nil {
			t.Errorf("%s: nil Package", f.RuleID)
			continue
		}
		if filepath.IsAbs(f.Location.Path) {
			t.Errorf("%s: path %q is absolute; it must be relative to the scan root",
				f.RuleID, f.Location.Path)
		}
	}
}

// TestConvertRelativizesPaths is the check that matters for identity: OSV reports
// absolute paths and the manifest path is a fingerprint input, so an absolute
// path would make identity depend on the checkout directory.
func TestConvertRelativizesPaths(t *testing.T) {
	t.Parallel()

	findings := convert(loadGolden(t), scanRoot)

	got, ok := findByRule(findings, "GHSA-3xgq-45jj-v275")
	if !ok {
		t.Fatal("cross-spawn advisory missing from converted findings")
	}
	if got.Location.Path != "package-lock.json" {
		t.Errorf("Location.Path = %q, want %q", got.Location.Path, "package-lock.json")
	}
}

// TestConvertFields pins the per-advisory mapping, including the fields that
// cross-tool merging depends on.
func TestConvertFields(t *testing.T) {
	t.Parallel()

	findings := convert(loadGolden(t), scanRoot)

	tests := []struct {
		ruleID    string
		severity  scan.Severity
		pkgName   string
		version   string
		ecosystem string
		fixedIn   string
		aliases   []string
	}{
		{
			// max_severity 7.7 -> high, which is also how Trivy grades it.
			ruleID: "GHSA-3xgq-45jj-v275", severity: scan.SeverityHigh,
			pkgName: "cross-spawn", version: "7.0.3", ecosystem: "npm",
			fixedIn: "7.0.5", aliases: []string{"CVE-2024-21538"},
		},
		{
			// max_severity 5.3 -> medium.
			ruleID: "GHSA-29mw-wpgm-hmr9", severity: scan.SeverityMedium,
			pkgName: "lodash", version: "4.17.20", ecosystem: "npm",
			fixedIn: "4.17.21", aliases: []string{"CVE-2020-28500"},
		},
		{
			// An advisory whose own alias list names two different CVEs.
			ruleID: "GHSA-35jh-r3h4-6jhm", severity: scan.SeverityHigh,
			pkgName: "lodash", version: "4.17.20", ecosystem: "npm",
			fixedIn: "4.17.21",
			aliases: []string{"CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"},
		},
		{
			// Synthetic: OSV's "Go" ecosystem and unprefixed version.
			ruleID: "GO-2025-3503", severity: scan.SeverityMedium,
			pkgName: "golang.org/x/net", version: "0.35.0", ecosystem: "Go",
			fixedIn: "0.36.0",
			aliases: []string{"CVE-2025-22870", "GHSA-qxp5-gwg8-xv66"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			t.Parallel()

			got, ok := findByRule(findings, tt.ruleID)
			if !ok {
				t.Fatalf("%s missing from converted findings", tt.ruleID)
			}
			if got.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", got.Severity, tt.severity)
			}
			if got.Package.Name != tt.pkgName {
				t.Errorf("Package.Name = %q, want %q", got.Package.Name, tt.pkgName)
			}
			if got.Package.Version != tt.version {
				t.Errorf("Package.Version = %q, want %q", got.Package.Version, tt.version)
			}
			if got.Package.Ecosystem != tt.ecosystem {
				t.Errorf("Package.Ecosystem = %q, want %q", got.Package.Ecosystem, tt.ecosystem)
			}
			if got.FixedIn != tt.fixedIn {
				t.Errorf("FixedIn = %q, want %q", got.FixedIn, tt.fixedIn)
			}
			if !slices.Equal(got.Aliases, tt.aliases) {
				t.Errorf("Aliases = %v, want %v", got.Aliases, tt.aliases)
			}
			if got.Title == "" {
				t.Error("Title is empty")
			}
		})
	}
}

// TestConvertMergesWithTrivyShapedFindings is the reason this adapter was built
// first. It asserts the identity contract end to end: a Trivy-shaped finding and
// the converted OSV finding for the same advisory must collapse into one issue,
// despite disagreeing on advisory ID, ecosystem name, and version prefix.
func TestConvertMergesWithTrivyShapedFindings(t *testing.T) {
	t.Parallel()

	osvFindings := convert(loadGolden(t), scanRoot)

	tests := []struct {
		name  string
		osvID string
		trivy scan.Finding
	}{
		{
			name:  "npm advisory, GHSA versus CVE",
			osvID: "GHSA-3xgq-45jj-v275",
			trivy: scan.Finding{
				Scanner:  "trivy",
				RuleID:   "CVE-2024-21538",
				Category: scan.CategoryVulnerability,
				Severity: scan.SeverityHigh,
				Location: scan.Location{Path: "package-lock.json"},
				Package: &scan.PackageRef{
					Name: "cross-spawn", Version: "7.0.3", Ecosystem: "npm",
				},
			},
		},
		{
			name:  "Go advisory, differing ecosystem and version vocabularies",
			osvID: "GO-2025-3503",
			trivy: scan.Finding{
				Scanner:  "trivy",
				RuleID:   "CVE-2025-22870",
				Category: scan.CategoryVulnerability,
				Severity: scan.SeverityMedium,
				Location: scan.Location{Path: "go.mod"},
				Package: &scan.PackageRef{
					// Trivy's spelling: "gomod", and a v-prefixed version.
					Name: "golang.org/x/net", Version: "v0.35.0", Ecosystem: "gomod",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fromOSV, ok := findByRule(osvFindings, tt.osvID)
			if !ok {
				t.Fatalf("%s missing from converted findings", tt.osvID)
			}

			fromTrivy := tt.trivy
			fromTrivy.Fingerprint = scan.Fingerprint(fromTrivy)

			if fromOSV.Fingerprint != fromTrivy.Fingerprint {
				t.Fatalf("fingerprints differ, so these will never merge:\n osv   %s = %s\n trivy %s = %s",
					fromOSV.RuleID, fromOSV.Fingerprint, fromTrivy.RuleID, fromTrivy.Fingerprint)
			}

			merged := scan.Dedup([]scan.Finding{fromTrivy, fromOSV})
			if len(merged) != 1 {
				t.Fatalf("Dedup produced %d findings, want 1", len(merged))
			}
			if got := merged[0].Agreement(); got != 2 {
				t.Errorf("Agreement() = %d, want 2", got)
			}
		})
	}
}

// TestSeverityBands pins the CVSS score to severity mapping. OSV reports a number
// where every other tool reports a word, so this conversion is the adapter's, and
// a wrong band silently distorts ranking.
func TestSeverityBands(t *testing.T) {
	t.Parallel()

	tests := []struct {
		score string
		want  scan.Severity
	}{
		{"9.8", scan.SeverityCritical},
		{"9.0", scan.SeverityCritical},
		{"8.9", scan.SeverityHigh},
		{"7.7", scan.SeverityHigh},
		{"7.0", scan.SeverityHigh},
		{"6.9", scan.SeverityMedium},
		{"4.0", scan.SeverityMedium},
		{"3.9", scan.SeverityLow},
		{"0.1", scan.SeverityLow},
		{"0.0", scan.SeverityInfo},
		{"", scan.SeverityUnknown},
		{"HIGH", scan.SeverityUnknown},
		{"-1", scan.SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.score, func(t *testing.T) {
			t.Parallel()

			if got := severity(tt.score); got != tt.want {
				t.Errorf("severity(%q) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

// TestFixedVersionIgnoresOtherPackages guards against reporting one package's fix
// as another's. Advisories routinely cover several packages.
func TestFixedVersionIgnoresOtherPackages(t *testing.T) {
	t.Parallel()

	v := vulnerability{
		ID: "GHSA-test",
		Affected: []affected{
			{
				Package: packageIdent{Name: "other-package", Ecosystem: "npm"},
				Ranges:  []versionRange{{Type: "SEMVER", Events: []rangeEvent{{Fixed: "9.9.9"}}}},
			},
			{
				Package: packageIdent{Name: "wanted", Ecosystem: "npm"},
				Ranges: []versionRange{
					// A GIT range holds commit hashes, not versions.
					{Type: "GIT", Events: []rangeEvent{{Fixed: "abc123def"}}},
					{Type: "SEMVER", Events: []rangeEvent{{Introduced: "1.0.0"}, {Fixed: "1.2.3"}}},
				},
			},
		},
	}

	if got := fixedVersion(v, "wanted"); got != "1.2.3" {
		t.Errorf("fixedVersion = %q, want %q", got, "1.2.3")
	}
	if got := fixedVersion(v, "absent"); got != "" {
		t.Errorf("fixedVersion for an unaffected package = %q, want empty", got)
	}
}

// TestGroupSeverityUngrouped covers an advisory that belongs to no group, which
// has no score to read.
func TestGroupSeverityUngrouped(t *testing.T) {
	t.Parallel()

	groups := []group{{IDs: []string{"GHSA-other"}, MaxSeverity: "9.9"}}
	if got := groupSeverity(groups, "GHSA-missing"); got != scan.SeverityUnknown {
		t.Errorf("groupSeverity = %q, want %q", got, scan.SeverityUnknown)
	}
}

// TestReferenceURLsOrdersAdvisoryFirst checks that the authoritative link leads.
func TestReferenceURLsOrdersAdvisoryFirst(t *testing.T) {
	t.Parallel()

	got := referenceURLs([]reference{
		{Type: "WEB", URL: "https://example.com/blog"},
		{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-1"},
		{Type: "WEB", URL: "https://example.com/blog"},
		{Type: "FIX", URL: ""},
	})

	want := []string{"https://nvd.nist.gov/vuln/detail/CVE-1", "https://example.com/blog"}
	if !slices.Equal(got, want) {
		t.Errorf("referenceURLs = %v, want %v", got, want)
	}
	if referenceURLs(nil) != nil {
		t.Error("referenceURLs(nil) should be nil")
	}
}

// TestRelativePathFallsBackToAbsolute documents the behavior when a source path
// lies outside the scan root: keep a usable absolute path rather than none.
func TestRelativePathFallsBackToAbsolute(t *testing.T) {
	t.Parallel()

	got := relativePath("/elsewhere/go.mod", scanRoot)
	if got != "/elsewhere/go.mod" {
		t.Errorf("relativePath = %q, want the cleaned absolute path", got)
	}
	if got := relativePath("", scanRoot); got != "" {
		t.Errorf("relativePath(\"\") = %q, want empty", got)
	}
}

// TestResultExit pins the exit-code contract. OSV-Scanner signals findings
// through the exit code and has no flag to disable that, so misreading it turns
// every vulnerable repository into a reported tool failure.
func TestResultExit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code int
		want bool
	}{
		{"packages scanned, nothing found", 0, true},
		{"vulnerabilities found", 1, true},
		{"top of the result range", 126, true},
		{"general error", 127, false},
		{"no packages found", 128, true},
		{"non-result error", 129, false},
		{"killed by signal", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := resultExit(tt.code); got != tt.want {
				t.Errorf("resultExit(%d) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}
