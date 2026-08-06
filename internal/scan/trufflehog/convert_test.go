package trufflehog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// goldenRoot is the fictional scan root the fixture's absolute paths were
// rewritten to. See testdata/README.md.
const goldenRoot = "/home/dev/pindrop/testdata/creds"

func loadGolden(t *testing.T) []finding {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "report.jsonl"))
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}

	// Decoded through the adapter's own loop rather than a bare Unmarshal, so the
	// fixture exercises the real framing.
	results, err := decode(raw)
	if err != nil {
		t.Fatalf("decoding golden fixture: %v", err)
	}
	return results
}

func findByRule(findings []scan.Finding, ruleID string) []scan.Finding {
	var out []scan.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func TestConvertGolden(t *testing.T) {
	t.Parallel()

	results := loadGolden(t)
	if got, want := len(results), 9; got != want {
		t.Fatalf("fixture has %d records, want %d", got, want)
	}

	findings := convert(results, goldenRoot, false)
	if got, want := len(findings), 9; got != want {
		t.Fatalf("converted %d findings, want %d", got, want)
	}

	for _, f := range findings {
		if got, want := f.Scanner, Name; got != want {
			t.Errorf("%s: Scanner = %q, want %q", f.RuleID, got, want)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s: Fingerprint is empty", f.RuleID)
		}
		if got, want := f.Category, scan.CategorySecret; got != want {
			t.Errorf("%s: Category = %q, want %q", f.RuleID, got, want)
		}
		if f.Severity == scan.SeverityUnknown {
			t.Errorf("%s: Severity is unknown", f.RuleID)
		}
		if f.Package != nil {
			t.Errorf("%s: Package = %+v, want nil", f.RuleID, f.Package)
		}
		if filepath.IsAbs(f.Location.Path) {
			t.Errorf("%s: Location.Path is absolute: %q", f.RuleID, f.Location.Path)
		}
		if f.Location.StartLine <= 0 {
			t.Errorf("%s: StartLine = %d, want > 0", f.RuleID, f.Location.StartLine)
		}
		if !strings.HasPrefix(f.Location.Snippet, "sha256:") {
			t.Errorf("%s: Snippet = %q, want a sha256: digest", f.RuleID, f.Location.Snippet)
		}
		if f.Title == "" {
			t.Errorf("%s: Title is empty", f.RuleID)
		}
		// A secret has no second identifier, so Aliases must stay empty — see
		// the note on secretFinding.
		if len(f.Aliases) != 0 {
			t.Errorf("%s: Aliases = %v, want none", f.RuleID, f.Aliases)
		}
	}
}

// The property the whole adapter is built around: no plaintext credential may
// reach a Finding. Asserted against the marshalled form, because that is what
// gets written to a report file and served over HTTP.
func TestNoPlaintextEscapes(t *testing.T) {
	t.Parallel()

	results := loadGolden(t)

	// The fixture's secret material is substituted, so seed each record with a
	// distinctive plaintext first. That makes this test independent of the
	// fixture's redaction and able to catch a future field being forwarded.
	const (
		rawSecret   = "PLAINTEXT-RAW-MUST-NOT-APPEAR"
		rawV2Secret = "PLAINTEXT-RAWV2-MUST-NOT-APPEAR"
		partSecret  = "PLAINTEXT-PART-MUST-NOT-APPEAR"
	)
	for i := range results {
		results[i].Raw = rawSecret
		results[i].RawV2 = rawV2Secret
		results[i].SecretParts = map[string]string{"token": partSecret}
	}

	findings := convert(results, goldenRoot, true)
	if len(findings) == 0 {
		t.Fatal("no findings to check")
	}

	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshalling findings: %v", err)
	}

	for _, secret := range []string{rawSecret, rawV2Secret, partSecret} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("marshalled findings contain plaintext %q", secret)
		}
	}
}

// "Redacted" upstream does not mean "carries nothing sensitive": for the
// PrivateKey detector it is the PEM header plus the first 32 characters of the key
// body. A report holding that is both a second copy and a string every other
// secret scanner will flag, so it must be capped.
func TestRedactedIsCapped(t *testing.T) {
	t.Parallel()

	// Verbatim shape from the captured fixture, before substitution.
	const pemRedacted = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAm4C7PsgypLedq6fr"

	got := redactedForDisplay(pemRedacted)

	if !strings.Contains(got, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("the PEM label should survive: %q", got)
	}
	if strings.Contains(got, "MIIEowIBAAKC") {
		t.Errorf("key body survived the cap: %q", got)
	}
	if n := len([]rune(got)); n > redactedDisplayLen+1 {
		t.Errorf("length = %d runes, want <= %d", n, redactedDisplayLen+1)
	}

	// Short identifying values must pass through untouched.
	for _, short := range []string{"AKIA2QJ4XZMTPWK7LNRV", "ghp_abcdef"} {
		if got := redactedForDisplay(short); got != short {
			t.Errorf("redactedForDisplay(%q) = %q, want it unchanged", short, got)
		}
	}

	if got := redactedForDisplay(""); got != "" {
		t.Errorf("empty input produced %q", got)
	}
}

// The same property, asserted through the whole conversion, which is the layer
// that actually reaches a report file.
func TestMessageCarriesNoKeyBody(t *testing.T) {
	t.Parallel()

	const keyBody = "MIIEowIBAAKCAQEAm4C7PsgypLedq6fr"

	res := finding{
		DetectorName: "PrivateKey",
		Raw:          "-----BEGIN RSA PRIVATE KEY-----\n" + keyBody + "\n-----END RSA PRIVATE KEY-----",
		Redacted:     "-----BEGIN RSA PRIVATE KEY-----\n" + keyBody,
		SourceMetadata: sourceMetadata{Data: metadataData{
			Filesystem: &filesystemMetadata{File: goldenRoot + "/id_rsa", Line: 1},
		}},
	}

	encoded, err := json.Marshal(convert([]finding{res}, goldenRoot, false))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(encoded), keyBody) {
		t.Errorf("marshalled finding contains key body:\n%s", encoded)
	}
}

// Redacted is display-only. It must reach the user through Message, and must not
// be what identity keys on.
func TestRedactedIsDisplayedButNotIdentity(t *testing.T) {
	t.Parallel()

	base := finding{
		DetectorName: "AWS",
		Raw:          "the-same-secret",
		Redacted:     "AKIAEXAMPLE",
		SourceMetadata: sourceMetadata{Data: metadataData{
			Filesystem: &filesystemMetadata{File: goldenRoot + "/.env", Line: 1},
		}},
	}

	withRedaction := convert([]finding{base}, goldenRoot, false)
	base.Redacted = ""
	withoutRedaction := convert([]finding{base}, goldenRoot, false)

	if got := withRedaction[0].Fingerprint; got != withoutRedaction[0].Fingerprint {
		t.Errorf("fingerprint changed when Redacted was dropped: %q vs %q",
			got, withoutRedaction[0].Fingerprint)
	}
	if !strings.Contains(withRedaction[0].Message, "AKIAEXAMPLE") {
		t.Errorf("Message should surface the redacted match:\n%s", withRedaction[0].Message)
	}
}

// Two credentials of one detector in one file are two problems. This is the case
// that catches an adapter which drops the digest — they would silently merge.
func TestRepeatedDetectorStaysDistinct(t *testing.T) {
	t.Parallel()

	findings := convert(loadGolden(t), goldenRoot, false)

	github := findByRule(findings, "Github")
	if len(github) < 2 {
		t.Fatalf("fixture should have at least 2 Github findings, got %d", len(github))
	}

	seen := make(map[string]bool, len(github))
	for _, f := range github {
		if seen[f.Fingerprint] {
			t.Errorf("duplicate fingerprint %s across distinct Github secrets", f.Fingerprint)
		}
		seen[f.Fingerprint] = true
	}
}

// Identity must not move when the file is edited above the secret, which is why
// the line number is not an input.
func TestFingerprintIgnoresLineNumber(t *testing.T) {
	t.Parallel()

	res := finding{
		DetectorName: "Stripe",
		Raw:          "sk_live_fixture",
		SourceMetadata: sourceMetadata{Data: metadataData{
			Filesystem: &filesystemMetadata{File: goldenRoot + "/config.yaml", Line: 4},
		}},
	}
	before := convert([]finding{res}, goldenRoot, false)

	res.SourceMetadata.Data.Filesystem.Line = 91
	after := convert([]finding{res}, goldenRoot, false)

	if before[0].Fingerprint != after[0].Fingerprint {
		t.Errorf("fingerprint moved with the line number: %q vs %q",
			before[0].Fingerprint, after[0].Fingerprint)
	}
	if after[0].Location.StartLine != 91 {
		t.Errorf("StartLine = %d, want 91", after[0].Location.StartLine)
	}
}

func TestSeverityMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		requested  bool
		verified   bool
		verifyErr  string
		want       scan.Severity
		wantReason string
	}{
		{
			name: "verification not requested", requested: false,
			want: scan.SeverityHigh,
			wantReason: "detected but nothing claimed; high so that enabling " +
				"verification is a visible promotion",
		},
		{
			name: "verified live", requested: true, verified: true,
			want:       scan.SeverityCritical,
			wantReason: "the issuer authenticated it",
		},
		{
			name: "verification errored", requested: true, verifyErr: "context deadline exceeded",
			want: scan.SeverityHigh,
			wantReason: "same evidentiary state as not having asked; grading it " +
				"lower lets a rate limit downgrade real tokens",
		},
		{
			name: "issuer says not live", requested: true,
			want:       scan.SeverityMedium,
			wantReason: "still a committed secret-shaped string",
		},
		{
			name: "verified wins over a stray error", requested: true, verified: true,
			verifyErr:  "some warning",
			want:       scan.SeverityCritical,
			wantReason: "Verified is the stronger signal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := finding{Verified: tt.verified, VerificationError: tt.verifyErr}
			if got := severity(res, tt.requested); got != tt.want {
				t.Errorf("severity() = %q, want %q (%s)", got, tt.want, tt.wantReason)
			}
		})
	}
}

// Unverified must never be critical, or the promotion that verification buys is
// invisible in the output.
func TestVerificationPromotesSeverity(t *testing.T) {
	t.Parallel()

	results := loadGolden(t)

	unverified := convert(results, goldenRoot, false)
	for _, f := range unverified {
		if f.Severity == scan.SeverityCritical {
			t.Errorf("%s is critical without verification", f.RuleID)
		}
	}

	verified := convert(results, goldenRoot, true)
	var critical int
	for _, f := range verified {
		if f.Severity == scan.SeverityCritical {
			critical++
		}
	}
	if critical == 0 {
		t.Error("no finding reached critical on the verification path")
	}
}

func TestActionable(t *testing.T) {
	t.Parallel()

	withFS := func(f *filesystemMetadata) sourceMetadata {
		return sourceMetadata{Data: metadataData{Filesystem: f}}
	}

	tests := []struct {
		name string
		res  finding
		want bool
	}{
		{
			name: "complete record",
			res: finding{
				DetectorName: "AWS", Raw: "x",
				SourceMetadata: withFS(&filesystemMetadata{File: "/a", Line: 1}),
			},
			want: true,
		},
		{
			name: "no detector name",
			res: finding{
				Raw:            "x",
				SourceMetadata: withFS(&filesystemMetadata{File: "/a", Line: 1}),
			},
			want: false,
		},
		{
			name: "no filesystem metadata",
			res:  finding{DetectorName: "AWS", Raw: "x"},
			want: false,
		},
		{
			name: "empty file path",
			res: finding{
				DetectorName: "AWS", Raw: "x",
				SourceMetadata: withFS(&filesystemMetadata{Line: 1}),
			},
			want: false,
		},
		{
			name: "nothing to digest",
			res: finding{
				DetectorName:   "AWS",
				SourceMetadata: withFS(&filesystemMetadata{File: "/a", Line: 1}),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := actionable(tt.res); got != tt.want {
				t.Errorf("actionable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvertDropsUnactionable(t *testing.T) {
	t.Parallel()

	results := []finding{
		{DetectorName: "AWS", Raw: "x", SourceMetadata: sourceMetadata{Data: metadataData{
			Filesystem: &filesystemMetadata{File: goldenRoot + "/.env", Line: 1},
		}}},
		{DetectorName: "Orphan", Raw: "y"}, // no filesystem metadata
	}

	findings := convert(results, goldenRoot, false)
	if got, want := len(findings), 1; got != want {
		t.Fatalf("len = %d, want %d", got, want)
	}
	if got, want := findings[0].RuleID, "AWS"; got != want {
		t.Errorf("RuleID = %q, want %q", got, want)
	}
}

func TestLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fs   *filesystemMetadata
		want int
	}{
		{"nil metadata", nil, 0},
		{"first line", &filesystemMetadata{Line: 1}, 1},
		{"zero means not line-scoped", &filesystemMetadata{Line: 0}, 0},
		{"negative is rejected", &filesystemMetadata{Line: -3}, 0},
		{"absurd value is rejected", &filesystemMetadata{Line: 1 << 40}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := line(tt.fs); got != tt.want {
				t.Errorf("line() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRelativePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file string
		root string
		want string
	}{
		{"below the root", goldenRoot + "/config/settings.yaml", goldenRoot, "config/settings.yaml"},
		{"at the root", goldenRoot + "/.env", goldenRoot, ".env"},
		{"empty file", "", goldenRoot, ""},
		{"escaping the root is kept as-is", "/etc/passwd", goldenRoot, "/etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := relativePath(&filesystemMetadata{File: tt.file}, tt.root)
			if got != tt.want {
				t.Errorf("relativePath() = %q, want %q", got, tt.want)
			}
		})
	}

	if got := relativePath(nil, goldenRoot); got != "" {
		t.Errorf("relativePath(nil) = %q, want empty", got)
	}
}

// The rotation guide is the most actionable thing in a record, so it must become
// a reference. Nothing else in ExtraData should.
func TestReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		extra map[string]string
		want  []string
	}{
		{
			name:  "rotation guide is surfaced",
			extra: map[string]string{"rotation_guide": "https://howtorotate.com/docs/tutorials/aws/"},
			want:  []string{"https://howtorotate.com/docs/tutorials/aws/"},
		},
		{
			name:  "other keys are not references",
			extra: map[string]string{"account": "722218765094"},
			want:  nil,
		},
		{
			name:  "non-URL values are dropped",
			extra: map[string]string{"rotation_guide": "see the docs"},
			want:  nil,
		},
		{name: "no extra data", extra: nil, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := references(finding{ExtraData: tt.extra})
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

// Messages must be byte-identical across runs, so map iteration order cannot
// leak into them.
func TestMessageIsDeterministic(t *testing.T) {
	t.Parallel()

	res := finding{
		DetectorName:        "Postgres",
		DetectorDescription: "A connection string.",
		ExtraData: map[string]string{
			"database": "appdb", "host": "db.invalid:5432",
			"sslmode": "<unset>", "username": "appuser",
		},
	}

	first := message(res, false)
	for range 20 {
		if got := message(res, false); got != first {
			t.Fatalf("message() is not deterministic:\n%q\nvs\n%q", first, got)
		}
	}
	if !strings.Contains(first, "--verify-secrets") {
		t.Errorf("unverified message should point at the flag:\n%s", first)
	}
}

func TestSnippet(t *testing.T) {
	t.Parallel()

	const secret = "ghp_fixturevalue"

	got := snippet(finding{Raw: secret})
	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("snippet() = %q, want a sha256: prefix", got)
	}
	if strings.Contains(got, secret) {
		t.Errorf("snippet() leaked the secret: %q", got)
	}
	if got != snippet(finding{Raw: secret}) {
		t.Error("snippet() is not deterministic")
	}
	if got == snippet(finding{Raw: secret + "x"}) {
		t.Error("different secrets produced the same digest")
	}
	// RawV2 is populated by only some detectors, so it must not affect identity.
	if got != snippet(finding{Raw: secret, RawV2: "id:" + secret}) {
		t.Error("RawV2 changed the digest")
	}
	if snippet(finding{}) != "" {
		t.Error("empty Raw should produce an empty snippet")
	}
}

func TestConvertEmptyInput(t *testing.T) {
	t.Parallel()

	got := convert(nil, goldenRoot, false)
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}
