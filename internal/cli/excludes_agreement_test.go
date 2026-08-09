package cli

import (
	"regexp"
	"slices"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// TestAllAdaptersHonorSharedExcludes is the test the codebase was missing.
//
// The Opengrep and TruffleHog adapters each used to carry a hand-written
// exclusion list, with a comment in one saying it mirrored the other and
// nothing anywhere checking that it did. Trivy and OSV-Scanner passed no
// exclusion flags at all. This asserts that one shared set reaches all four,
// each in the syntax that tool actually accepts.
//
// It lives in internal/cli rather than internal/scan because scan must not
// import an adapter — that is the import cycle CLAUDE.md warns about — and the
// CLI is already the one place that imports all four.
func TestAllAdaptersHonorSharedExcludes(t *testing.T) {
	t.Parallel()

	excludes := scan.DefaultExcludes()

	args := adapterArgs(t, excludes)

	for _, dir := range excludes.Dirs {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()

			// Trivy: doublestar globs, and both depth forms are required
			// because "**/x" does not match "./x" at the scan root.
			if !hasFlagValue(args.trivy, "--skip-dirs", dir) ||
				!hasFlagValue(args.trivy, "--skip-dirs", "**/"+dir) {
				t.Errorf("trivy is missing --skip-dirs for %q", dir)
			}

			// OSV-Scanner: directory names, no glob prefix.
			if !hasFlagValue(args.osv, "--experimental-exclude", dir) {
				t.Errorf("osv is missing --experimental-exclude for %q", dir)
			}

			// Opengrep: gitignore syntax, trailing slash to mean "directory".
			if !hasFlagValue(args.opengrep, "--exclude", dir+"/") {
				t.Errorf("opengrep is missing --exclude %q/", dir)
			}

			// TruffleHog: anchored regular expressions in a file.
			if !matchesAny(t, args.trufflehog, dir+"/some/file") {
				t.Errorf("trufflehog does not exclude paths under %q", dir)
			}
		})
	}
}

// TestAllAdaptersLeaveEnvFilesScannable is the cross-adapter half of the
// invariant that scan.Excludes exists to protect.
//
// The virtualenv directories env, venv and .venv are excluded; a .env file is
// a credential store and must reach every scanner that could report it. The
// hazard is per-tool translation, so it is checked per tool.
func TestAllAdaptersLeaveEnvFilesScannable(t *testing.T) {
	t.Parallel()

	excludes := scan.DefaultExcludes()
	args := adapterArgs(t, excludes)

	envFiles := []string{".env", "app/.env", "srv/.env.production"}

	for _, path := range envFiles {
		if matchesAny(t, args.trufflehog, path) {
			t.Errorf("trufflehog would skip %q, blinding the secret scanner", path)
		}
	}

	// A bare directory name in either of these two would match a file.
	for _, bare := range []string{"env", ".env", "venv"} {
		if hasFlagValue(args.opengrep, "--exclude", bare) {
			t.Errorf("opengrep --exclude %q lacks the trailing slash that makes it a directory", bare)
		}
		if hasFlagValue(args.trivy, "--skip-files", bare) {
			t.Errorf("trivy emitted directory %q as --skip-files", bare)
		}
	}
}

// adapterArgvs is the argv (or exclude-file patterns) each adapter produces.
type adapterArgvs struct {
	trivy      []string
	osv        []string
	opengrep   []string
	trufflehog []string
}

// adapterArgs builds each adapter's exclusion arguments from one shared set.
func adapterArgs(t *testing.T, excludes scan.Excludes) adapterArgvs {
	t.Helper()

	return adapterArgvs{
		trivy:      excludes.TrivyArgs(),
		osv:        excludes.OSVArgs(),
		opengrep:   excludes.OpengrepArgs(),
		trufflehog: excludes.TruffleHogPatterns(),
	}
}

// hasFlagValue reports whether args contains flag immediately followed by value.
func hasFlagValue(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// matchesAny reports whether any pattern matches path, compiling each the way
// TruffleHog would.
func matchesAny(t *testing.T, patterns []string, path string) bool {
	t.Helper()

	return slices.ContainsFunc(patterns, func(p string) bool {
		re, err := regexp.Compile(p)
		if err != nil {
			t.Fatalf("pattern %q does not compile: %v", p, err)
		}
		return re.MatchString(path)
	})
}

// TestScannerRegistryCoversEveryAdapter guards the agreement test itself: if a
// fifth scanner is added and not accounted for above, this fails rather than
// the new adapter silently escaping the shared exclusion set.
func TestScannerRegistryCoversEveryAdapter(t *testing.T) {
	t.Parallel()

	got := make([]string, 0, 4)
	for _, s := range scannerRegistry(&scanOptions{}) {
		got = append(got, s.Name())
	}
	slices.Sort(got)

	want := []string{"opengrep", "osv", "trivy", "trufflehog"}
	if !slices.Equal(got, want) {
		t.Fatalf("registry has %v, but the exclusion agreement test knows about %v.\n"+
			"Add the new adapter's translation to scan.Excludes and to this test.",
			got, want)
	}
}
