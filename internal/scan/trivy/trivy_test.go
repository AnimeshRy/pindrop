package trivy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// Scanner must satisfy the scan.Scanner contract at compile time.
var _ scan.Scanner = (*Scanner)(nil)

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	s := New()

	if s.binary != "trivy" {
		t.Errorf("binary = %q, want %q", s.binary, "trivy")
	}
	if s.timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", s.timeout, defaultTimeout)
	}
	if len(s.scanners) != len(DefaultScanners) {
		t.Errorf("scanners = %v, want %v", s.scanners, DefaultScanners)
	}
}

// TestOptionsIgnoreZeroValues checks that options degrade to the default rather
// than silently configuring a scanner that cannot run.
func TestOptionsIgnoreZeroValues(t *testing.T) {
	t.Parallel()

	s := New(
		WithBinary(""),
		WithTimeout(0),
		WithScanners(),
	)

	if s.binary != "trivy" {
		t.Errorf("binary = %q, want the default retained", s.binary)
	}
	if s.timeout != defaultTimeout {
		t.Errorf("timeout = %v, want the default retained", s.timeout)
	}
	if len(s.scanners) != len(DefaultScanners) {
		t.Errorf("scanners = %v, want the default retained", s.scanners)
	}
}

func TestOptionsApply(t *testing.T) {
	t.Parallel()

	s := New(
		WithBinary("/opt/trivy"),
		WithTimeout(30*time.Second),
		WithScanners("vuln"),
		WithCacheDir("/tmp/cache"),
	)

	if s.binary != "/opt/trivy" {
		t.Errorf("binary = %q, want %q", s.binary, "/opt/trivy")
	}
	if s.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want %v", s.timeout, 30*time.Second)
	}
	if len(s.scanners) != 1 || s.scanners[0] != "vuln" {
		t.Errorf("scanners = %v, want [vuln]", s.scanners)
	}
	if s.cacheDir != "/tmp/cache" {
		t.Errorf("cacheDir = %q, want %q", s.cacheDir, "/tmp/cache")
	}
}

// TestPreflightMissingBinary is the failure users hit most often. It must
// produce actionable guidance wrapping scan.ErrUnavailable, not a raw exec
// error.
func TestPreflightMissingBinary(t *testing.T) {
	t.Parallel()

	s := New(WithBinary("pindrop-trivy-does-not-exist"))

	err := s.Preflight(context.Background())
	if err == nil {
		t.Fatal("Preflight() error = nil, want an error")
	}
	if !errors.Is(err, scan.ErrUnavailable) {
		t.Errorf("Preflight() error = %v, want it to wrap scan.ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "trivy.dev") {
		t.Errorf("Preflight() error = %q, want it to include install guidance", err)
	}
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b    string
		wantCmp int // -1 less, 0 equal, 1 greater
		wantOK  bool
	}{
		{"0.72.0", "0.50.0", 1, true},
		{"0.50.0", "0.72.0", -1, true},
		{"0.50.0", "0.50.0", 0, true},
		{"1.0.0", "0.99.99", 1, true},
		{"v0.72.0", "0.72.0", 0, true},
		{"0.72", "0.72.0", 0, true},
		{"0.72.1", "0.72", 1, true},
		{"0.73.0-rc1", "0.72.0", 1, true},
		{"dev", "0.50.0", 0, false},
		{"", "0.50.0", 0, false},
		{"0.72.0", "nightly", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			t.Parallel()

			cmp, ok := compareVersions(tt.a, tt.b)
			if ok != tt.wantOK {
				t.Fatalf("compareVersions(%q, %q) ok = %v, want %v", tt.a, tt.b, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if sign(cmp) != tt.wantCmp {
				t.Errorf("compareVersions(%q, %q) = %d, want sign %d", tt.a, tt.b, cmp, tt.wantCmp)
			}
		})
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// TestArgs pins the invariants that were previously only asserted in comments.
func TestArgs(t *testing.T) {
	t.Parallel()

	s := New()
	got := s.args("/tmp/target", scan.Excludes{})

	// Without --exit-code 0, Trivy exits non-zero when it finds vulnerabilities,
	// making "the tool failed" indistinguishable from "the code has bugs".
	if i := slices.Index(got, "--exit-code"); i < 0 || got[i+1] != "0" {
		t.Errorf("--exit-code 0 missing from %q", got)
	}
	if got[0] != "fs" {
		t.Errorf("subcommand = %q, want %q", got[0], "fs")
	}
	// The target must come last; Trivy takes it positionally.
	if got[len(got)-1] != "/tmp/target" {
		t.Errorf("target is not the final argument: %q", got)
	}
	for _, want := range []string{"--format", "json", "--quiet"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q missing from %q", want, got)
		}
	}
}

func TestArgsCacheDir(t *testing.T) {
	t.Parallel()

	without := New().args("/t", scan.Excludes{})
	if slices.Contains(without, "--cache-dir") {
		t.Errorf("--cache-dir emitted with no cache directory set: %q", without)
	}

	with := New(WithCacheDir("/cache")).args("/t", scan.Excludes{})
	if i := slices.Index(with, "--cache-dir"); i < 0 || with[i+1] != "/cache" {
		t.Errorf("--cache-dir /cache missing from %q", with)
	}
}

// TestArgsSkipsExcludedDirs covers the ordinary case: with the license
// sub-scanner off, every excluded directory reaches Trivy as --skip-dirs, in
// both the bare and **/-prefixed forms.
func TestArgsSkipsExcludedDirs(t *testing.T) {
	t.Parallel()

	s := New(WithScanners("vuln", "secret"))
	got := s.args("/t", scan.Excludes{Dirs: []string{"node_modules"}})

	for _, want := range []string{"node_modules", "**/node_modules"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q missing from %q", want, got)
		}
	}
}

// TestArgsKeepsLicenseSourceDirs is the exception that earns its keep: Trivy
// identifies npm licenses by reading LICENSE files under node_modules and Go
// licenses from vendor/, so skipping them would silently delete the copyleft
// findings actionableLicense exists to surface.
//
// Those directories' other findings are still filtered — scan.Run applies the
// same exclusions to everything that comes back — so only the walk cost differs.
func TestArgsKeepsLicenseSourceDirs(t *testing.T) {
	t.Parallel()

	excludes := scan.Excludes{Dirs: []string{"node_modules", "vendor", "dist"}}
	got := New(WithScanners("vuln", "license")).args("/t", excludes)

	for _, kept := range []string{"node_modules", "vendor"} {
		if slices.Contains(got, kept) {
			t.Errorf("%q was skipped, which blinds the license scanner: %q", kept, got)
		}
	}
	// An ordinary build directory is still skipped.
	if !slices.Contains(got, "dist") {
		t.Errorf("dist should still be skipped: %q", got)
	}
}
