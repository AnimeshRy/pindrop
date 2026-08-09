package scan_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// withFingerprint returns a finding whose identity is set literally, so a test
// can state which findings are meant to be the same without depending on how
// [scan.Fingerprint] hashes. Tests that are about identity itself call
// scan.Fingerprint instead.
func withFingerprint(fp string) scan.Finding {
	return scan.Finding{
		Fingerprint: fp,
		Scanner:     "trivy",
		RuleID:      fp,
		Category:    scan.CategoryVulnerability,
		Severity:    scan.SeverityHigh,
	}
}

// fingerprints returns the fingerprint of each finding, which is what every
// partition assertion below actually cares about.
func fingerprints(findings []scan.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Fingerprint)
	}
	return out
}

func TestStatusValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status scan.Status
		want   bool
	}{
		{"new", scan.StatusNew, true},
		{"open", scan.StatusOpen, true},
		{"fixed", scan.StatusFixed, true},
		{"regressed", scan.StatusRegressed, true},
		{"an unknown value", scan.Status("triaged"), false},
		{"the zero value", scan.Status(""), false},
		{"a known value in the wrong case", scan.Status("NEW"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("Status(%q).Valid() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

// TestStatusOpen pins which statuses describe a problem the user still has.
// Getting this wrong either hides live findings or reports fixed ones as
// outstanding.
func TestStatusOpen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status scan.Status
		want   bool
	}{
		{"new", scan.StatusNew, true},
		{"open", scan.StatusOpen, true},
		{"regressed", scan.StatusRegressed, true},
		{"fixed", scan.StatusFixed, false},
		{"an unknown value is not open", scan.Status("triaged"), false},
		{"the zero value is not open", scan.Status(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.status.Open(); got != tt.want {
				t.Errorf("Status(%q).Open() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestDiff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		previous, current []scan.Finding
		wantNew           []string
		wantStillOpen     []string
		wantFixed         []string
	}{
		{
			name:          "all three transitions in one diff",
			previous:      []scan.Finding{withFingerprint("a"), withFingerprint("b")},
			current:       []scan.Finding{withFingerprint("b"), withFingerprint("c")},
			wantNew:       []string{"c"},
			wantStillOpen: []string{"b"},
			wantFixed:     []string{"a"},
		},
		{
			// The first-ever scan: with nothing to compare against, everything
			// is new and nothing can have been fixed.
			name:     "empty previous",
			previous: nil,
			current:  []scan.Finding{withFingerprint("a"), withFingerprint("b")},
			wantNew:  []string{"a", "b"},
		},
		{
			name:      "empty current",
			previous:  []scan.Finding{withFingerprint("a"), withFingerprint("b")},
			current:   nil,
			wantFixed: []string{"a", "b"},
		},
		{
			name: "both empty",
		},
		{
			// A repeated fingerprint is what Dedup exists to prevent, but Diff
			// must not depend on having been handed deduplicated input.
			name:          "duplicate fingerprints in current",
			previous:      []scan.Finding{withFingerprint("a")},
			current:       []scan.Finding{withFingerprint("a"), withFingerprint("a"), withFingerprint("b")},
			wantNew:       []string{"b"},
			wantStillOpen: []string{"a"},
		},
		{
			name:      "duplicate fingerprints in previous",
			previous:  []scan.Finding{withFingerprint("a"), withFingerprint("a")},
			current:   nil,
			wantFixed: []string{"a"},
		},
		{
			// An empty fingerprint is not an identity, so it matches nothing:
			// two of them are two findings, not one, and one in previous can
			// never be shown as still open.
			name:      "empty fingerprints are all distinct",
			previous:  []scan.Finding{{RuleID: "broken-before"}},
			current:   []scan.Finding{{RuleID: "broken-a"}, {RuleID: "broken-b"}},
			wantNew:   []string{"", ""},
			wantFixed: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := scan.Diff(tt.previous, tt.current)

			if want := tt.wantNew; !slices.Equal(fingerprints(got.New), want) {
				t.Errorf("New = %q, want %q", fingerprints(got.New), want)
			}
			if want := tt.wantStillOpen; !slices.Equal(fingerprints(got.StillOpen), want) {
				t.Errorf("StillOpen = %q, want %q", fingerprints(got.StillOpen), want)
			}
			if want := tt.wantFixed; !slices.Equal(fingerprints(got.Fixed), want) {
				t.Errorf("Fixed = %q, want %q", fingerprints(got.Fixed), want)
			}
		})
	}
}

// TestDiffTracksAFindingThatMoved is the property the whole feature rests on:
// an unrelated edit above a finding must not report it as fixed and
// reintroduced. It is built from real scan.Fingerprint calls rather than
// literal identities, so a regression in fingerprint stability fails here too
// and not only in fingerprint_test.go.
func TestDiffTracksAFindingThatMoved(t *testing.T) {
	t.Parallel()

	before := scan.Finding{
		Scanner:  "opengrep",
		RuleID:   "pindrop.go.sql-injection",
		Category: scan.CategoryCode,
		Severity: scan.SeverityHigh,
		Location: scan.Location{
			Path:      "internal/api/users.go",
			StartLine: 42,
			Snippet:   `db.Query("SELECT * FROM users WHERE id = " + id)`,
		},
	}
	after := before
	after.Location.StartLine = 108
	after.Location.EndLine = 108

	before.Fingerprint = scan.Fingerprint(before)
	after.Fingerprint = scan.Fingerprint(after)

	if before.Fingerprint != after.Fingerprint {
		t.Fatalf("a line move changed the fingerprint (%s versus %s); every edit "+
			"above a finding would report it as fixed and reintroduced",
			before.Fingerprint, after.Fingerprint)
	}

	got := scan.Diff([]scan.Finding{before}, []scan.Finding{after})
	if len(got.StillOpen) != 1 {
		t.Fatalf("StillOpen has %d findings, want 1", len(got.StillOpen))
	}
	if got.StillOpen[0].Location.StartLine != 108 {
		t.Errorf("StillOpen kept the stale location %d, want the current 108",
			got.StillOpen[0].Location.StartLine)
	}
	if len(got.New) != 0 || len(got.Fixed) != 0 {
		t.Errorf("a moved finding was reported as %d new and %d fixed, want 0 and 0",
			len(got.New), len(got.Fixed))
	}
}

// TestDiffIsDeterministic guards the property that lets the same two runs be
// rendered into a table and served over HTTP without reordering between calls.
// Map iteration in Go is deliberately randomized, so an implementation that
// ranged over a map would fail this within a few repetitions.
func TestDiffIsDeterministic(t *testing.T) {
	t.Parallel()

	var previous, current []scan.Finding
	for i := range 50 {
		previous = append(previous, withFingerprint(fmt.Sprintf("old-%02d", i)))
		current = append(current, withFingerprint(fmt.Sprintf("new-%02d", i)))
	}
	// Overlap the two runs so all three partitions are non-empty.
	shared := withFingerprint("shared")
	previous = append(previous, shared)
	current = append(current, shared)

	want := scan.Diff(previous, current)
	for range 20 {
		got := scan.Diff(previous, current)
		if !slices.Equal(fingerprints(got.New), fingerprints(want.New)) {
			t.Fatalf("New order varies between calls:\n %q\n %q",
				fingerprints(got.New), fingerprints(want.New))
		}
		if !slices.Equal(fingerprints(got.StillOpen), fingerprints(want.StillOpen)) {
			t.Fatalf("StillOpen order varies between calls:\n %q\n %q",
				fingerprints(got.StillOpen), fingerprints(want.StillOpen))
		}
		if !slices.Equal(fingerprints(got.Fixed), fingerprints(want.Fixed)) {
			t.Fatalf("Fixed order varies between calls:\n %q\n %q",
				fingerprints(got.Fixed), fingerprints(want.Fixed))
		}
	}

	// Input order, not sorted order: the caller decides how findings are
	// ranked, and Diff must not quietly reorder them.
	if fingerprints(want.New)[0] != "new-00" || fingerprints(want.Fixed)[0] != "old-00" {
		t.Errorf("Diff did not preserve input order: New[0] = %q, Fixed[0] = %q",
			want.New[0].Fingerprint, want.Fixed[0].Fingerprint)
	}
}

// TestDiffNeverReportsRegressed records the deliberate limit of the no-store
// path: two sets cannot tell "never seen before" from "seen, fixed, and back".
func TestDiffNeverReportsRegressed(t *testing.T) {
	t.Parallel()

	got := scan.Diff([]scan.Finding{withFingerprint("a")},
		[]scan.Finding{withFingerprint("a"), withFingerprint("returned")})

	for _, d := range got.Deltas() {
		if d.Status == scan.StatusRegressed {
			t.Errorf("Diff reported %q as regressed; only a history store can know that",
				d.Finding.Fingerprint)
		}
		if !d.Status.Valid() {
			t.Errorf("Diff produced the invalid status %q", d.Status)
		}
	}
}

func TestDiffResultDeltas(t *testing.T) {
	t.Parallel()

	got := scan.Diff(
		[]scan.Finding{withFingerprint("a"), withFingerprint("b")},
		[]scan.Finding{withFingerprint("b"), withFingerprint("c")},
	).Deltas()

	want := []scan.Delta{
		{Status: scan.StatusNew, Finding: withFingerprint("c")},
		{Status: scan.StatusOpen, Finding: withFingerprint("b")},
		{Status: scan.StatusFixed, Finding: withFingerprint("a")},
	}
	if len(got) != len(want) {
		t.Fatalf("Deltas() returned %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Status != want[i].Status ||
			got[i].Finding.Fingerprint != want[i].Finding.Fingerprint {
			t.Errorf("Deltas()[%d] = (%q, %q), want (%q, %q)",
				i, got[i].Status, got[i].Finding.Fingerprint,
				want[i].Status, want[i].Finding.Fingerprint)
		}
	}

	if deltas := (scan.DiffResult{}).Deltas(); deltas != nil {
		t.Errorf("Deltas() on an empty result = %v, want nil", deltas)
	}
}
