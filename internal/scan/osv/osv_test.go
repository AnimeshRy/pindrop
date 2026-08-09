package osv

import (
	"slices"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// TestArgs pins the invariants that were previously only asserted in comments.
func TestArgs(t *testing.T) {
	t.Parallel()

	got := New().args("/tmp/target", scan.Excludes{})

	if got[0] != "scan" || got[1] != "source" {
		t.Errorf("subcommand = %q, want %q", got[:2], []string{"scan", "source"})
	}
	// The scan display renders to stderr, and any concurrent stderr writer
	// shreds it. OSV-Scanner writes progress and walk statistics there at the
	// default level, so this flag is load-bearing for the TUI, not cosmetic.
	if i := slices.Index(got, "--verbosity"); i < 0 || got[i+1] != "error" {
		t.Errorf("--verbosity error missing from %q", got)
	}
	for _, want := range []string{"--format", "json", "--recursive"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q missing from %q", want, got)
		}
	}
	if got[len(got)-1] != "/tmp/target" {
		t.Errorf("target is not the final argument: %q", got)
	}
}

// TestArgsCallAnalysis covers the default: call analysis is off, because it is
// slow and its results are advisory.
func TestArgsCallAnalysis(t *testing.T) {
	t.Parallel()

	off := New().args("/t", scan.Excludes{})
	if i := slices.Index(off, "--no-call-analysis"); i < 0 || off[i+1] != "all" {
		t.Errorf("--no-call-analysis all missing from %q", off)
	}

	on := New(WithCallAnalysis(true)).args("/t", scan.Excludes{})
	if slices.Contains(on, "--no-call-analysis") {
		t.Errorf("--no-call-analysis emitted despite call analysis being enabled: %q", on)
	}
}

// TestArgsExcludeFlagName pins the upstream flag name.
//
// It carries an experimental- prefix, so it is not a stable contract. Pinning
// it here means an upstream rename fails a test rather than a user's scan —
// and because scan.Run filters the results anyway, a rename degrades speed
// rather than correctness.
func TestArgsExcludeFlagName(t *testing.T) {
	t.Parallel()

	got := New().args("/t", scan.Excludes{Dirs: []string{"node_modules"}})

	i := slices.Index(got, "--experimental-exclude")
	if i < 0 || got[i+1] != "node_modules" {
		t.Errorf("--experimental-exclude node_modules missing from %q", got)
	}
}

// TestArgsOmitsFileExcludes records that the flag excludes directories only,
// which is why scan.Run's filter is the correctness mechanism here.
func TestArgsOmitsFileExcludes(t *testing.T) {
	t.Parallel()

	got := New().args("/t", scan.Excludes{Files: []string{"*.min.js"}})

	if slices.Contains(got, "*.min.js") {
		t.Errorf("a file pattern reached a directory-only flag: %q", got)
	}
}
