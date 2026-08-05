package scan_test

import (
	"slices"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// fingerprinted returns f with its fingerprint computed, the way an adapter
// hands findings to the rest of the system.
func fingerprinted(f scan.Finding) scan.Finding {
	f.Fingerprint = scan.Fingerprint(f)
	return f
}

// TestDedupMergesAcrossScanners is the specification for the product's core
// claim: two tools reporting one problem is one issue, not two.
//
// Each case pairs a Trivy-shaped finding with an OSV-Scanner-shaped one for the
// same underlying advisory, spelled the way each tool actually spells it.
func TestDedupMergesAcrossScanners(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b scan.Finding
	}{
		{
			name: "CVE-primary versus GHSA-primary with the CVE aliased",
			a: scan.Finding{
				Scanner:  "trivy",
				RuleID:   "CVE-2024-21538",
				Category: scan.CategoryVulnerability,
				Severity: scan.SeverityHigh,
				Location: scan.Location{Path: "package-lock.json"},
				Package: &scan.PackageRef{
					Name: "cross-spawn", Version: "7.0.3", Ecosystem: "npm",
				},
			},
			b: scan.Finding{
				Scanner:  "osv",
				RuleID:   "GHSA-3xgq-45jj-v275",
				Aliases:  []string{"CVE-2024-21538"},
				Category: scan.CategoryVulnerability,
				Severity: scan.SeverityHigh,
				Location: scan.Location{Path: "package-lock.json"},
				Package: &scan.PackageRef{
					Name: "cross-spawn", Version: "7.0.3", Ecosystem: "npm",
				},
			},
		},
		{
			name: "Go ecosystem and version vocabularies differ",
			a: scan.Finding{
				Scanner:  "trivy",
				RuleID:   "CVE-2025-22870",
				Category: scan.CategoryVulnerability,
				Severity: scan.SeverityMedium,
				Location: scan.Location{Path: "go.mod"},
				Package: &scan.PackageRef{
					Name: "golang.org/x/net", Version: "v0.35.0", Ecosystem: "gomod",
				},
			},
			b: scan.Finding{
				Scanner:  "osv",
				RuleID:   "GO-2025-3503",
				Aliases:  []string{"CVE-2025-22870", "GHSA-qxp5-gwg8-xv66"},
				Category: scan.CategoryVulnerability,
				Severity: scan.SeverityMedium,
				Location: scan.Location{Path: "go.mod"},
				Package: &scan.PackageRef{
					Name: "golang.org/x/net", Version: "0.35.0", Ecosystem: "Go",
				},
			},
		},
		{
			name: "Python index name versus tool name",
			a: scan.Finding{
				Scanner:  "trivy",
				RuleID:   "CVE-2024-35195",
				Category: scan.CategoryVulnerability,
				Severity: scan.SeverityMedium,
				Location: scan.Location{Path: "requirements.txt"},
				Package: &scan.PackageRef{
					Name: "requests", Version: "2.31.0", Ecosystem: "pip",
				},
			},
			b: scan.Finding{
				Scanner:  "osv",
				RuleID:   "GHSA-9wx4-h78v-vm56",
				Aliases:  []string{"CVE-2024-35195"},
				Category: scan.CategoryVulnerability,
				Severity: scan.SeverityMedium,
				Location: scan.Location{Path: "requirements.txt"},
				Package: &scan.PackageRef{
					Name: "requests", Version: "2.31.0", Ecosystem: "PyPI",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, b := fingerprinted(tt.a), fingerprinted(tt.b)
			if a.Fingerprint != b.Fingerprint {
				t.Fatalf("fingerprints differ, so the findings can never merge:\n %s = %s\n %s = %s",
					tt.a.Scanner, a.Fingerprint, tt.b.Scanner, b.Fingerprint)
			}

			got := scan.Dedup([]scan.Finding{a, b})
			if len(got) != 1 {
				t.Fatalf("Dedup returned %d findings, want 1", len(got))
			}

			if want := []string{"osv", "trivy"}; !slices.Equal(want, got[0].Scanners) {
				t.Errorf("Scanners = %v, want %v", got[0].Scanners, want)
			}
			if got[0].Agreement() != 2 {
				t.Errorf("Agreement() = %d, want 2", got[0].Agreement())
			}
		})
	}
}

// TestDedupIsOrderIndependent guards the property that makes merged findings
// safe to persist and diff: the same inputs in a different order must produce
// byte-identical output, because scanners finish in whatever order they finish.
func TestDedupIsOrderIndependent(t *testing.T) {
	t.Parallel()

	trivy := fingerprinted(scan.Finding{
		Scanner:  "trivy",
		RuleID:   "CVE-2024-21538",
		Category: scan.CategoryVulnerability,
		Severity: scan.SeverityMedium, // disagrees with osv below
		Title:    "cross-spawn ReDoS",
		Location: scan.Location{Path: "package-lock.json"},
		Package: &scan.PackageRef{
			Name: "cross-spawn", Version: "7.0.3", Ecosystem: "npm",
		},
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-21538"},
	})
	osv := fingerprinted(scan.Finding{
		Scanner:  "osv",
		RuleID:   "GHSA-3xgq-45jj-v275",
		Aliases:  []string{"CVE-2024-21538"},
		Category: scan.CategoryVulnerability,
		Severity: scan.SeverityHigh,
		Location: scan.Location{Path: "package-lock.json", StartLine: 412},
		Package: &scan.PackageRef{
			Name: "cross-spawn", Version: "7.0.3", Ecosystem: "npm",
		},
		FixedIn:    "7.0.5",
		References: []string{"https://osv.dev/GHSA-3xgq-45jj-v275"},
	})

	forward := scan.Dedup([]scan.Finding{trivy, osv})
	reverse := scan.Dedup([]scan.Finding{osv, trivy})

	if len(forward) != 1 || len(reverse) != 1 {
		t.Fatalf("expected one finding each, got %d and %d", len(forward), len(reverse))
	}

	// RuleID is the one field that legitimately differs: it records whichever
	// tool reported first, and the canonical ID lives in the fingerprint.
	// Everything that affects what the user sees must match.
	f, r := forward[0], reverse[0]
	if f.Severity != scan.SeverityHigh || r.Severity != scan.SeverityHigh {
		t.Errorf("severity should be the highest reported either way, got %q and %q",
			f.Severity, r.Severity)
	}
	if f.FixedIn != "7.0.5" || r.FixedIn != "7.0.5" {
		t.Errorf("FixedIn should survive from whichever tool knew it, got %q and %q",
			f.FixedIn, r.FixedIn)
	}
	if f.Location.StartLine != 412 || r.Location.StartLine != 412 {
		t.Errorf("the more specific location should win, got %d and %d",
			f.Location.StartLine, r.Location.StartLine)
	}
	if !slices.Equal(f.References, r.References) {
		t.Errorf("references depend on order: forward %v, reverse %v", f.References, r.References)
	}
	if !slices.Equal(f.Scanners, r.Scanners) {
		t.Errorf("scanners depend on order: forward %v, reverse %v", f.Scanners, r.Scanners)
	}
	if len(f.References) != 2 {
		t.Errorf("expected the union of both reference lists, got %v", f.References)
	}
}

// TestDedupPreservesDistinctFindings checks the failure that would be worse than
// a duplicate: merging two findings that are not the same problem.
func TestDedupPreservesDistinctFindings(t *testing.T) {
	t.Parallel()

	base := scan.Finding{
		Scanner:  "trivy",
		RuleID:   "CVE-2024-21538",
		Category: scan.CategoryVulnerability,
		Severity: scan.SeverityHigh,
		Location: scan.Location{Path: "package-lock.json"},
		Package: &scan.PackageRef{
			Name: "cross-spawn", Version: "7.0.3", Ecosystem: "npm",
		},
	}

	tests := []struct {
		name   string
		mutate func(scan.Finding) scan.Finding
	}{
		{
			name: "different advisory",
			mutate: func(f scan.Finding) scan.Finding {
				f.RuleID = "CVE-2024-21539"
				return f
			},
		},
		{
			name: "different package version",
			mutate: func(f scan.Finding) scan.Finding {
				f.Package = &scan.PackageRef{
					Name: "cross-spawn", Version: "7.0.4", Ecosystem: "npm",
				}
				return f
			},
		},
		{
			name: "same package in another service of a monorepo",
			mutate: func(f scan.Finding) scan.Finding {
				f.Location.Path = "services/api/package-lock.json"
				return f
			},
		},
		{
			name: "an ecosystem that only looks similar",
			mutate: func(f scan.Finding) scan.Finding {
				f.Package = &scan.PackageRef{
					Name: "cross-spawn", Version: "7.0.3", Ecosystem: "cargo",
				}
				return f
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := scan.Dedup([]scan.Finding{
				fingerprinted(base),
				fingerprinted(tt.mutate(base)),
			})
			if len(got) != 2 {
				t.Fatalf("Dedup collapsed distinct findings into %d, want 2", len(got))
			}
		})
	}
}

// TestDedupPassesThroughUnfingerprintedFindings ensures an adapter bug surfaces
// as duplicate rows rather than being silently hidden by collapsing every
// fingerprint-less finding into one.
func TestDedupPassesThroughUnfingerprintedFindings(t *testing.T) {
	t.Parallel()

	got := scan.Dedup([]scan.Finding{
		{Scanner: "broken", RuleID: "A"},
		{Scanner: "broken", RuleID: "B"},
	})
	if len(got) != 2 {
		t.Fatalf("Dedup returned %d findings, want 2", len(got))
	}
	for _, f := range got {
		if f.Scanners != nil {
			t.Errorf("unfingerprinted finding should carry no scanner list, got %v", f.Scanners)
		}
	}
}

// TestDedupSingleScannerSetsAgreement covers the common case: one tool, one
// finding, agreement of one rather than zero.
func TestDedupSingleScannerSetsAgreement(t *testing.T) {
	t.Parallel()

	got := scan.Dedup([]scan.Finding{fingerprinted(vulnFinding())})
	if len(got) != 1 {
		t.Fatalf("Dedup returned %d findings, want 1", len(got))
	}
	if want := []string{"trivy"}; !slices.Equal(want, got[0].Scanners) {
		t.Errorf("Scanners = %v, want %v", got[0].Scanners, want)
	}
	if got[0].Agreement() != 1 {
		t.Errorf("Agreement() = %d, want 1", got[0].Agreement())
	}
}

// TestDedupEmpty documents that no findings is not an error condition.
func TestDedupEmpty(t *testing.T) {
	t.Parallel()

	if got := scan.Dedup(nil); got != nil {
		t.Errorf("Dedup(nil) = %v, want nil", got)
	}
}
