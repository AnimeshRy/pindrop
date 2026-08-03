package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// sampleResults returns results spanning every category and a range of
// severities, so renderers are exercised across their full mapping tables.
func sampleResults() []scan.Result {
	findings := []scan.Finding{
		{
			Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Scanner:     "trivy",
			RuleID:      "CVE-2024-21538",
			Category:    scan.CategoryVulnerability,
			Severity:    scan.SeverityHigh,
			Title:       "cross-spawn: regular expression denial of service",
			Location:    scan.Location{Path: "package-lock.json"},
			Package: &scan.PackageRef{
				Name: "cross-spawn", Version: "7.0.3", Ecosystem: "npm",
			},
			FixedIn:    "7.0.5",
			References: []string{"https://avd.aquasec.com/nvd/cve-2024-21538"},
		},
		{
			Fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Scanner:     "trivy",
			RuleID:      "stripe-access-token",
			Category:    scan.CategorySecret,
			Severity:    scan.SeverityCritical,
			Title:       "Stripe",
			Location:    scan.Location{Path: ".env", StartLine: 3, EndLine: 3},
		},
		{
			Fingerprint: "cccccccccccccccccccccccccccccccc",
			Scanner:     "trivy",
			RuleID:      "AVD-DS-0002",
			Category:    scan.CategoryMisconfiguration,
			Severity:    scan.SeverityLow,
			Title:       "Image user should not be 'root'",
			Location:    scan.Location{Path: "Dockerfile", StartLine: 1},
		},
	}

	return []scan.Result{{
		Scanner:   "trivy",
		Target:    scan.Target{Path: "/tmp/app"},
		StartedAt: time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
		Duration:  3200 * time.Millisecond,
		Findings:  findings,
	}}
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    report.Format
		wantErr bool
	}{
		{in: "table", want: report.FormatTable},
		{in: "json", want: report.FormatJSON},
		{in: "sarif", want: report.FormatSARIF},
		{in: "JSON", want: report.FormatJSON},
		{in: " sarif ", want: report.FormatSARIF},
		{in: "xml", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			got, err := report.ParseFormat(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseFormat(%q) error = nil, want an error", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFormat(%q) error = %v, want nil", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestTableOrdersBySeverity guards the product's central promise: the most
// urgent thing is the first thing you read.
func TestTableOrdersBySeverity(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := report.Table(&buf, sampleResults(), report.Options{}); err != nil {
		t.Fatalf("Table() error = %v, want nil", err)
	}
	out := buf.String()

	critical := strings.Index(out, "CRITICAL")
	high := strings.Index(out, "HIGH")
	low := strings.Index(out, "LOW")

	if critical < 0 || high < 0 || low < 0 {
		t.Fatalf("Table() output is missing severities:\n%s", out)
	}
	if critical >= high || high >= low {
		t.Errorf("Table() ordered severities critical=%d high=%d low=%d, want ascending positions", critical, high, low)
	}
	if !strings.Contains(out, "3 findings") {
		t.Errorf("Table() output missing summary count:\n%s", out)
	}
}

func TestTableNoColorByDefault(t *testing.T) {
	t.Parallel()

	var plain, colored bytes.Buffer
	if err := report.Table(&plain, sampleResults(), report.Options{}); err != nil {
		t.Fatalf("Table() error = %v", err)
	}
	if err := report.Table(&colored, sampleResults(), report.Options{Color: true}); err != nil {
		t.Fatalf("Table() error = %v", err)
	}

	if strings.Contains(plain.String(), "\033[") {
		t.Error("Table() with Color=false emitted ANSI escapes")
	}
	if !strings.Contains(colored.String(), "\033[") {
		t.Error("Table() with Color=true emitted no ANSI escapes")
	}
}

func TestTableLimit(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := report.Table(&buf, sampleResults(), report.Options{Limit: 1}); err != nil {
		t.Fatalf("Table() error = %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "and 2 more") {
		t.Errorf("Table() with Limit=1 did not note the hidden findings:\n%s", out)
	}
	// The truncation note must not lie about the total.
	if !strings.Contains(out, "3 findings") {
		t.Errorf("Table() summary should still count all findings:\n%s", out)
	}
}

func TestTableEmpty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := report.Table(&buf, nil, report.Options{}); err != nil {
		t.Fatalf("Table() error = %v, want nil", err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Errorf("Table() with no results = %q, want a no-findings message", buf.String())
	}
}

func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := report.JSON(&buf, sampleResults()); err != nil {
		t.Fatalf("JSON() error = %v, want nil", err)
	}

	doc, err := report.DecodeDocument(&buf)
	if err != nil {
		t.Fatalf("DecodeDocument() error = %v, want nil", err)
	}

	if doc.SchemaVersion != report.DocumentSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", doc.SchemaVersion, report.DocumentSchemaVersion)
	}
	if len(doc.Findings) != 3 {
		t.Errorf("Findings = %d, want 3", len(doc.Findings))
	}
	if len(doc.Scans) != 1 {
		t.Fatalf("Scans = %d, want 1", len(doc.Scans))
	}
	if doc.Scans[0].DurationMS != 3200 {
		t.Errorf("Scans[0].DurationMS = %d, want 3200", doc.Scans[0].DurationMS)
	}
	// Severity order must survive serialization.
	if doc.Findings[0].Severity != scan.SeverityCritical {
		t.Errorf("Findings[0].Severity = %q, want critical", doc.Findings[0].Severity)
	}
}

// TestJSONEmptyFindingsIsArray matters for the frontend: a null would force a
// null check in every consumer.
func TestJSONEmptyFindingsIsArray(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := report.JSON(&buf, nil); err != nil {
		t.Fatalf("JSON() error = %v, want nil", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got := string(raw["findings"]); got != "[]" {
		t.Errorf("findings = %s, want []", got)
	}
}

func TestDecodeDocumentRejectsUnknownSchema(t *testing.T) {
	t.Parallel()

	_, err := report.DecodeDocument(strings.NewReader(`{"schemaVersion": 999}`))
	if err == nil {
		t.Fatal("DecodeDocument() error = nil, want a schema version error")
	}
	if !strings.Contains(err.Error(), "999") {
		t.Errorf("DecodeDocument() error = %q, want it to name the bad version", err)
	}
}

func TestSARIFStructure(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := report.SARIF(&buf, sampleResults()); err != nil {
		t.Fatalf("SARIF() error = %v, want nil", err)
	}

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				RuleIndex           int               `json:"ruleIndex"`
				Level               string            `json:"level"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Locations           []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}

	run := log.Runs[0]
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("rules = %d, want 3", len(run.Tool.Driver.Rules))
	}

	for i, res := range run.Results {
		// ruleIndex must actually address the declared rule, or consumers
		// render the wrong description.
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("results[%d].ruleIndex = %d, out of range", i, res.RuleIndex)
			continue
		}
		if got := run.Tool.Driver.Rules[res.RuleIndex].ID; got != res.RuleID {
			t.Errorf("results[%d] ruleIndex points at %q, want %q", i, got, res.RuleID)
		}
		if res.PartialFingerprints["pindropFingerprint/v1"] == "" {
			t.Errorf("results[%d] has no partial fingerprint", i)
		}
	}

	// A dependency finding has no meaningful line, and SARIF forbids
	// startLine: 0, so its region must be omitted entirely.
	for _, res := range run.Results {
		if res.RuleID != "CVE-2024-21538" {
			continue
		}
		if region := res.Locations[0].PhysicalLocation.Region; region != nil {
			t.Errorf("dependency finding has region %+v, want none", region)
		}
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity scan.Severity
		want     string
	}{
		{scan.SeverityCritical, "error"},
		{scan.SeverityHigh, "error"},
		{scan.SeverityMedium, "warning"},
		{scan.SeverityLow, "note"},
		{scan.SeverityInfo, "note"},
		{scan.SeverityUnknown, "none"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			t.Parallel()

			results := []scan.Result{{
				Scanner: "test",
				Findings: []scan.Finding{{
					RuleID:   "R1",
					Category: scan.CategoryCode,
					Severity: tt.severity,
					Location: scan.Location{Path: "a.go", StartLine: 1},
				}},
			}}

			var buf bytes.Buffer
			if err := report.SARIF(&buf, results); err != nil {
				t.Fatalf("SARIF() error = %v", err)
			}
			if !strings.Contains(buf.String(), `"level": "`+tt.want+`"`) {
				t.Errorf("SARIF() for %q did not map to level %q:\n%s", tt.severity, tt.want, buf.String())
			}
		})
	}
}

func TestWriteDispatchesByFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format report.Format
		want   string
	}{
		{report.FormatTable, "SEVERITY"},
		{report.FormatJSON, `"schemaVersion"`},
		{report.FormatSARIF, `"$schema"`},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			if err := report.Write(&buf, tt.format, sampleResults(), report.Options{}); err != nil {
				t.Fatalf("Write() error = %v, want nil", err)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("Write(%q) output missing %q", tt.format, tt.want)
			}
		})
	}
}
