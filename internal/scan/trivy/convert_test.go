package trivy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// loadReport decodes the golden Trivy report. Keeping conversion tests driven
// by a captured real report means they run in CI without Trivy installed.
func loadReport(t *testing.T) report {
	t.Helper()

	raw, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatalf("reading golden report: %v", err)
	}

	var rep report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("decoding golden report: %v", err)
	}
	return rep
}

// findByRule locates a converted finding by rule ID.
func findByRule(t *testing.T, findings []scan.Finding, ruleID string) scan.Finding {
	t.Helper()

	for _, f := range findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	t.Fatalf("no finding with RuleID %q among %d findings", ruleID, len(findings))
	return scan.Finding{}
}

func TestConvertCountsEveryClass(t *testing.T) {
	t.Parallel()

	findings := convert(loadReport(t))

	// 2 vulnerabilities + 1 misconfiguration + 1 secret + 1 license.
	if got, want := len(findings), 5; got != want {
		t.Fatalf("convert() produced %d findings, want %d", got, want)
	}

	counts := make(map[scan.Category]int)
	for _, f := range findings {
		counts[f.Category]++
	}

	want := map[scan.Category]int{
		scan.CategoryVulnerability:    2,
		scan.CategoryMisconfiguration: 1,
		scan.CategorySecret:           1,
		scan.CategoryLicense:          1,
	}
	for category, wantN := range want {
		if got := counts[category]; got != wantN {
			t.Errorf("category %q count = %d, want %d", category, got, wantN)
		}
	}
}

func TestConvertVulnerability(t *testing.T) {
	t.Parallel()

	got := findByRule(t, convert(loadReport(t)), "CVE-2024-21538")

	if got.Scanner != Name {
		t.Errorf("Scanner = %q, want %q", got.Scanner, Name)
	}
	if got.Severity != scan.SeverityHigh {
		t.Errorf("Severity = %q, want %q", got.Severity, scan.SeverityHigh)
	}
	if got.FixedIn != "7.0.5" {
		t.Errorf("FixedIn = %q, want %q", got.FixedIn, "7.0.5")
	}
	if got.Location.Path != "package-lock.json" {
		t.Errorf("Location.Path = %q, want %q", got.Location.Path, "package-lock.json")
	}

	if got.Package == nil {
		t.Fatal("Package = nil, want a package reference")
	}
	if got.Package.Name != "cross-spawn" {
		t.Errorf("Package.Name = %q, want %q", got.Package.Name, "cross-spawn")
	}
	if got.Package.Version != "7.0.3" {
		t.Errorf("Package.Version = %q, want %q", got.Package.Version, "7.0.3")
	}
	if got.Package.Ecosystem != "npm" {
		t.Errorf("Package.Ecosystem = %q, want %q", got.Package.Ecosystem, "npm")
	}

	// The primary URL must lead, and the duplicate copy of it must be dropped.
	wantRefs := []string{
		"https://avd.aquasec.com/nvd/cve-2024-21538",
		"https://github.com/moxystudio/node-cross-spawn/commit/5ff3a07",
	}
	if len(got.References) != len(wantRefs) {
		t.Fatalf("References = %v, want %v", got.References, wantRefs)
	}
	for i, want := range wantRefs {
		if got.References[i] != want {
			t.Errorf("References[%d] = %q, want %q", i, got.References[i], want)
		}
	}
}

// TestConvertSparseVulnerability covers Trivy's documented minimum: only
// VulnerabilityID, PkgName, InstalledVersion, and Severity are guaranteed.
func TestConvertSparseVulnerability(t *testing.T) {
	t.Parallel()

	got := findByRule(t, convert(loadReport(t)), "CVE-2025-0001")

	if got.Severity != scan.SeverityCritical {
		t.Errorf("Severity = %q, want %q", got.Severity, scan.SeverityCritical)
	}
	// With no Title in the report, one must be synthesized rather than blank.
	if want := "CVE-2025-0001 in left-pad"; got.Title != want {
		t.Errorf("Title = %q, want %q", got.Title, want)
	}
	if got.References != nil {
		t.Errorf("References = %v, want nil", got.References)
	}
}

func TestConvertMisconfiguration(t *testing.T) {
	t.Parallel()

	got := findByRule(t, convert(loadReport(t)), "DS-0002")

	if got.Category != scan.CategoryMisconfiguration {
		t.Errorf("Category = %q, want %q", got.Category, scan.CategoryMisconfiguration)
	}
	if got.Location.StartLine != 1 {
		t.Errorf("Location.StartLine = %d, want 1", got.Location.StartLine)
	}
	if want := "FROM node:18-alpine"; got.Location.Snippet != want {
		t.Errorf("Location.Snippet = %q, want %q", got.Location.Snippet, want)
	}
	if !strings.Contains(got.Message, "Resolution:") {
		t.Errorf("Message = %q, want it to fold in the resolution", got.Message)
	}
}

func TestConvertSecret(t *testing.T) {
	t.Parallel()

	got := findByRule(t, convert(loadReport(t)), "github-pat")

	if got.Category != scan.CategorySecret {
		t.Errorf("Category = %q, want %q", got.Category, scan.CategorySecret)
	}
	if got.Severity != scan.SeverityCritical {
		t.Errorf("Severity = %q, want %q", got.Severity, scan.SeverityCritical)
	}
	if got.Location.Path != ".env" {
		t.Errorf("Location.Path = %q, want %q", got.Location.Path, ".env")
	}
	// Trivy redacts the secret before we ever see it; the stored value must
	// stay masked so a Pindrop report is never itself a credential leak.
	if strings.Contains(got.Message, "ghp_") {
		t.Errorf("Message = %q, want the redacted form", got.Message)
	}
}

func TestConvertLicense(t *testing.T) {
	t.Parallel()

	got := findByRule(t, convert(loadReport(t)), "GPL-3.0")

	if got.Category != scan.CategoryLicense {
		t.Errorf("Category = %q, want %q", got.Category, scan.CategoryLicense)
	}
	if got.Package == nil || got.Package.Name != "some-pkg" {
		t.Errorf("Package = %+v, want a reference to some-pkg", got.Package)
	}
}

// TestConvertFingerprintsEveryFinding guards the invariant that the Scanner
// contract promises: no finding leaves an adapter without an identity.
func TestConvertFingerprintsEveryFinding(t *testing.T) {
	t.Parallel()

	findings := convert(loadReport(t))
	seen := make(map[string]bool, len(findings))

	for _, f := range findings {
		if f.Fingerprint == "" {
			t.Errorf("finding %q has an empty fingerprint", f.RuleID)
			continue
		}
		if seen[f.Fingerprint] {
			t.Errorf("finding %q reuses fingerprint %s", f.RuleID, f.Fingerprint)
		}
		seen[f.Fingerprint] = true
	}
}

// TestConvertEmptyReport covers Trivy omitting Results entirely on a clean
// scan, which would panic or misreport if decoded carelessly.
func TestConvertEmptyReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{"results omitted", `{"SchemaVersion":2,"ArtifactName":"x"}`},
		{"results null", `{"SchemaVersion":2,"Results":null}`},
		{"results empty", `{"SchemaVersion":2,"Results":[]}`},
		{"result with no findings", `{"SchemaVersion":2,"Results":[{"Target":"go.mod"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var rep report
			if err := json.Unmarshal([]byte(tt.raw), &rep); err != nil {
				t.Fatalf("Unmarshal() error = %v, want nil", err)
			}
			if got := convert(rep); len(got) != 0 {
				t.Errorf("convert() = %d findings, want 0", len(got))
			}
		})
	}
}

func TestSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want scan.Severity
	}{
		{"CRITICAL", scan.SeverityCritical},
		{"HIGH", scan.SeverityHigh},
		{"MEDIUM", scan.SeverityMedium},
		{"LOW", scan.SeverityLow},
		{"INFO", scan.SeverityInfo},
		{"critical", scan.SeverityCritical},
		{" High ", scan.SeverityHigh},
		{"UNKNOWN", scan.SeverityUnknown},
		{"", scan.SeverityUnknown},
		{"NONSENSE", scan.SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			if got := severity(tt.in); got != tt.want {
				t.Errorf("severity(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestPermissiveLicensesAreDropped guards the product's core promise.
//
// Trivy classifies every license it identifies, so a clean repository still
// produces one entry per permissive dependency. Scanning Pindrop itself once
// returned 24 MIT/Apache/BSD/ISC entries against 8 real problems — noise that
// buries exactly what the tool exists to surface.
func TestPermissiveLicensesAreDropped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		category string
		want     bool
	}{
		{"forbidden", true},
		{"restricted", true},
		{"reciprocal", true},
		{"Restricted", true},
		{"notice", false},
		{"permissive", false},
		{"unencumbered", false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			t.Parallel()

			rep := report{
				SchemaVersion: 2,
				Results: []result{{
					Target: "package-lock.json",
					Class:  "license",
					Type:   "npm",
					Licenses: []license{{
						Severity: "LOW",
						Category: tt.category,
						PkgName:  "some-pkg",
						Name:     "SOME-LICENSE",
					}},
				}},
			}

			got := len(convert(rep))
			want := 0
			if tt.want {
				want = 1
			}
			if got != want {
				t.Errorf("convert() kept %d findings for category %q, want %d", got, tt.category, want)
			}
		})
	}
}

// TestLicenseDescriptionExplainsWhy — a user who is not a lawyer needs to know
// why a license is a problem, not just its name.
func TestLicenseDescriptionExplainsWhy(t *testing.T) {
	t.Parallel()

	rep := report{
		SchemaVersion: 2,
		Results: []result{{
			Target: "package-lock.json",
			Class:  "license",
			Type:   "npm",
			Licenses: []license{{
				Severity: "HIGH",
				Category: "restricted",
				PkgName:  "copyleft-pkg",
				Name:     "GPL-3.0",
			}},
		}},
	}

	findings := convert(rep)
	if len(findings) != 1 {
		t.Fatalf("convert() = %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Message, "copyleft") {
		t.Errorf("Message = %q, want an explanation mentioning copyleft", findings[0].Message)
	}
}
