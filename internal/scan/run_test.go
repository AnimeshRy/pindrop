package scan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// stubScanner is a test double whose availability and findings are fixed at
// construction.
type stubScanner struct {
	name      string
	preflight error
	findings  []scan.Finding
}

func (s stubScanner) Name() string { return s.name }

func (s stubScanner) Preflight(context.Context) error { return s.preflight }

func (s stubScanner) Scan(_ context.Context, target scan.Target) (scan.Result, error) {
	return scan.Result{Scanner: s.name, Target: target, Findings: s.findings}, nil
}

// names extracts scanner names for comparison.
func names(scanners []scan.Scanner) []string {
	out := make([]string, 0, len(scanners))
	for _, s := range scanners {
		out = append(out, s.Name())
	}
	return out
}

// TestUsablePartitions covers the property that keeps the zero-setup first run
// working: an optional scanner being absent must reduce coverage, not abort the
// scan. Only having nothing left to run is fatal, and that is the caller's call.
func TestUsablePartitions(t *testing.T) {
	t.Parallel()

	missing := &scan.UnavailableError{Scanner: "osv", Reason: "not found"}

	tests := []struct {
		name       string
		scanners   []scan.Scanner
		wantUsable []string
		wantErr    bool
	}{
		{
			name: "all available",
			scanners: []scan.Scanner{
				stubScanner{name: "trivy"},
				stubScanner{name: "osv"},
			},
			wantUsable: []string{"trivy", "osv"},
		},
		{
			name: "one missing is skipped, order preserved",
			scanners: []scan.Scanner{
				stubScanner{name: "trivy"},
				stubScanner{name: "osv", preflight: missing},
				stubScanner{name: "zizmor"},
			},
			wantUsable: []string{"trivy", "zizmor"},
			wantErr:    true,
		},
		{
			name: "none available",
			scanners: []scan.Scanner{
				stubScanner{name: "trivy", preflight: missing},
				stubScanner{name: "osv", preflight: missing},
			},
			wantUsable: []string{},
			wantErr:    true,
		},
		{
			name:       "no scanners at all",
			scanners:   nil,
			wantUsable: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			usable, err := scan.Usable(context.Background(), tt.scanners)

			got := names(usable)
			if len(got) != len(tt.wantUsable) {
				t.Fatalf("usable = %v, want %v", got, tt.wantUsable)
			}
			for i := range got {
				if got[i] != tt.wantUsable[i] {
					t.Fatalf("usable = %v, want %v", got, tt.wantUsable)
				}
			}

			if tt.wantErr && err == nil {
				t.Error("expected an error describing the unavailable scanners")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, scan.ErrUnavailable) {
				t.Errorf("error should wrap ErrUnavailable, got %v", err)
			}
		})
	}
}

// TestFindingsDedupsAcrossResults checks that flattening two scanners' results
// merges their overlapping findings, since that is what every renderer relies on.
func TestFindingsDedupsAcrossResults(t *testing.T) {
	t.Parallel()

	shared := scan.Finding{
		RuleID:   "CVE-2024-21538",
		Category: scan.CategoryVulnerability,
		Severity: scan.SeverityHigh,
		Location: scan.Location{Path: "package-lock.json"},
		Package: &scan.PackageRef{
			Name: "cross-spawn", Version: "7.0.3", Ecosystem: "npm",
		},
	}

	fromTrivy := shared
	fromTrivy.Scanner = "trivy"
	fromTrivy.Fingerprint = scan.Fingerprint(fromTrivy)

	// Same problem, reported under the GHSA identifier with the CVE aliased.
	fromOSV := shared
	fromOSV.Scanner = "osv"
	fromOSV.RuleID = "GHSA-3xgq-45jj-v275"
	fromOSV.Aliases = []string{"CVE-2024-21538"}
	fromOSV.Fingerprint = scan.Fingerprint(fromOSV)

	got := scan.Findings([]scan.Result{
		{Scanner: "trivy", Findings: []scan.Finding{fromTrivy}},
		{Scanner: "osv", Findings: []scan.Finding{fromOSV}},
	})

	if len(got) != 1 {
		t.Fatalf("Findings returned %d findings, want 1 merged", len(got))
	}
	if agreement := got[0].Agreement(); agreement != 2 {
		t.Errorf("Agreement() = %d, want 2", agreement)
	}
}
