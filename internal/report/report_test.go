package report_test

import (
	"bytes"
	"encoding/json"
	"regexp"
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

// TestDecodeDocumentSchemaRange pins the readable range and, more importantly,
// that the two failure directions are told apart: "upgrade pindrop" and "run a
// fresh scan" are different instructions, and a user who gets the wrong one
// wastes their time.
func TestDecodeDocumentSchemaRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		wantErr  bool
		contains []string
	}{
		{
			name: "missing version",
			body: `{"generatedAt":"2026-08-02T12:00:00Z"}`,
			// Not "old" — a file with no version is most often not ours at all.
			wantErr:  true,
			contains: []string{"no schemaVersion", "pindrop scan"},
		},
		{
			name:     "explicit zero",
			body:     `{"schemaVersion":0}`,
			wantErr:  true,
			contains: []string{"no schemaVersion"},
		},
		{
			name:     "too old",
			body:     `{"schemaVersion":-1}`,
			wantErr:  true,
			contains: []string{"-1", "older pindrop", "fresh scan"},
		},
		{
			name:     "too new",
			body:     `{"schemaVersion":999}`,
			wantErr:  true,
			contains: []string{"999", "newer pindrop", "upgrade"},
		},
		{
			name: "minimum readable",
			body: `{"schemaVersion":1,"findings":[]}`,
		},
		{
			name: "current",
			body: `{"schemaVersion":2,"findings":[]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := report.DecodeDocument(strings.NewReader(tt.body))
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("DecodeDocument() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("DecodeDocument() error = nil, want an error")
			}
			for _, want := range tt.contains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("DecodeDocument() error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

// TestDecodeV1Document is the reason the version check is a range: a document
// written before scan history existed must keep decoding, with the fields it
// predates left at their zero values. The JSON is written out literally rather
// than built from the current struct, so a future field rename cannot make this
// test pass by rewriting the fixture along with the code.
func TestDecodeV1Document(t *testing.T) {
	t.Parallel()

	const v1 = `{
  "schemaVersion": 1,
  "generatedAt": "2026-08-02T12:00:00Z",
  "tool": {"name": "pindrop", "version": "0.1.0"},
  "scans": [
    {"scanner": "trivy", "target": "/tmp/app", "startedAt": "2026-08-02T12:00:00Z", "durationMs": 3200, "findings": 1}
  ],
  "findings": [
    {"fingerprint": "aaaa", "scanner": "trivy", "ruleId": "CVE-2024-21538", "category": "vulnerability", "severity": "high"}
  ]
}`

	doc, err := report.DecodeDocument(strings.NewReader(v1))
	if err != nil {
		t.Fatalf("DecodeDocument() error = %v, want nil", err)
	}

	if doc.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", doc.SchemaVersion)
	}
	if len(doc.Findings) != 1 || doc.Findings[0].Fingerprint != "aaaa" {
		t.Errorf("Findings = %+v, want the single v1 finding", doc.Findings)
	}
	if len(doc.Scans) != 1 || doc.Scans[0].DurationMS != 3200 {
		t.Errorf("Scans = %+v, want the single v1 scan", doc.Scans)
	}

	// Everything added since v1 must be absent, not invented.
	if doc.RunID != "" {
		t.Errorf("RunID = %q, want empty", doc.RunID)
	}
	if doc.Repo != nil {
		t.Errorf("Repo = %+v, want nil", doc.Repo)
	}
	if doc.Status != nil {
		t.Errorf("Status = %v, want nil", doc.Status)
	}
}

// TestDocumentHistoryRoundTrip covers the fields a persisted run adds.
func TestDocumentHistoryRoundTrip(t *testing.T) {
	t.Parallel()

	doc := report.NewDocument(sampleResults())
	doc.RunID = "01JCE7F3ZQ9V4T0KX2A6M8B1YQ"
	doc.Repo = &report.Repo{
		ID:     "repo-7f3a",
		Name:   "pindrop",
		Path:   "/tmp/app",
		Origin: "git@github.com:AnimeshRy/pindrop.git",
		Branch: "main",
		Commit: "42b9daf",
	}
	doc.Status = map[string]scan.Status{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": scan.StatusOpen,
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": scan.StatusNew,
		"cccccccccccccccccccccccccccccccc": scan.StatusRegressed,
	}

	var buf bytes.Buffer
	if err := report.WriteDocument(&buf, report.FormatJSON, doc, report.Options{}); err != nil {
		t.Fatalf("WriteDocument() error = %v, want nil", err)
	}

	got, err := report.DecodeDocument(&buf)
	if err != nil {
		t.Fatalf("DecodeDocument() error = %v, want nil", err)
	}

	if got.RunID != doc.RunID {
		t.Errorf("RunID = %q, want %q", got.RunID, doc.RunID)
	}
	if got.Repo == nil || *got.Repo != *doc.Repo {
		t.Errorf("Repo = %+v, want %+v", got.Repo, doc.Repo)
	}
	if len(got.Status) != len(doc.Status) {
		t.Fatalf("Status = %v, want %v", got.Status, doc.Status)
	}
	for fp, want := range doc.Status {
		if got.Status[fp] != want {
			t.Errorf("Status[%s] = %q, want %q", fp, got.Status[fp], want)
		}
	}
}

// TestDocumentWithoutHistoryMatchesV1Bytes protects every existing consumer: a
// scan that was not persisted must serialize exactly as it did before scan
// history existed, so that the only visible difference is the version number.
// The expected bytes come from a struct carrying only the v1 fields, not from
// the current one.
func TestDocumentWithoutHistoryMatchesV1Bytes(t *testing.T) {
	t.Parallel()

	type v1Document struct {
		SchemaVersion int                  `json:"schemaVersion"`
		GeneratedAt   time.Time            `json:"generatedAt"`
		Tool          report.Tool          `json:"tool"`
		Scans         []report.ScanSummary `json:"scans"`
		Findings      []scan.Finding       `json:"findings"`
	}

	doc := report.NewDocument(sampleResults())

	var got bytes.Buffer
	if err := report.WriteDocument(&got, report.FormatJSON, doc, report.Options{}); err != nil {
		t.Fatalf("WriteDocument() error = %v, want nil", err)
	}

	var want bytes.Buffer
	enc := json.NewEncoder(&want)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v1Document{
		SchemaVersion: 1,
		GeneratedAt:   doc.GeneratedAt,
		Tool:          doc.Tool,
		Scans:         doc.Scans,
		Findings:      doc.Findings,
	}); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	// Normalize away the one difference that is supposed to exist.
	normalized := strings.Replace(got.String(),
		`"schemaVersion": 2`, `"schemaVersion": 1`, 1)
	if normalized != want.String() {
		t.Errorf("document bytes differ from v1 layout:\ngot:\n%s\nwant:\n%s", normalized, want.String())
	}
}

// TestWriteDocumentMatchesWrite pins the decomposition: rendering a document
// and rendering the results it was built from must not drift apart.
func TestWriteDocumentMatchesWrite(t *testing.T) {
	t.Parallel()

	for _, format := range report.Formats {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()

			results := sampleResults()
			doc := report.NewDocument(results)

			var fromResults, fromDoc bytes.Buffer
			if err := report.Write(&fromResults, format, results, report.Options{}); err != nil {
				t.Fatalf("Write() error = %v, want nil", err)
			}
			if err := report.WriteDocument(&fromDoc, format, doc, report.Options{}); err != nil {
				t.Fatalf("WriteDocument() error = %v, want nil", err)
			}

			got, want := fromDoc.String(), fromResults.String()
			if format == report.FormatJSON {
				// Only the generation timestamp can legitimately differ: the
				// two calls build their documents at different instants.
				got = generatedAt.ReplaceAllString(got, "")
				want = generatedAt.ReplaceAllString(want, "")
			}
			if got != want {
				t.Errorf("WriteDocument(%q) differs from Write:\ngot:\n%s\nwant:\n%s", format, got, want)
			}
		})
	}
}

// generatedAt matches the one field two independently built documents may
// legitimately disagree on.
var generatedAt = regexp.MustCompile(`"generatedAt": "[^"]*"`)

func TestWriteDocumentUnknownFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := report.WriteDocument(&buf, report.Format("xml"), report.Document{}, report.Options{}); err == nil {
		t.Fatal("WriteDocument() error = nil, want an error")
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
