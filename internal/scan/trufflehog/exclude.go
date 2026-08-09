package trufflehog

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// secretNoiseExcludes are excluded from secret scanning only, and are
// deliberately absent from [scan.DefaultExcludes].
//
// These are regular expressions matched against the path, not globs:
// --exclude-globs is git-only, and the filesystem source accepts patterns
// solely through a file.
//
// Lockfiles are a genuine trade rather than a free win. They are dense with
// high-entropy integrity hashes that no detector should be asked to reason
// about, but a real token can legitimately appear in a private registry URL
// inside one. Excluding them accepts that false negative in exchange for the
// adapter being usable at all on a JavaScript repository.
//
// They live here rather than in the shared set because they are dependency
// manifests: excluding them globally would blind Trivy and OSV-Scanner to
// every dependency in the tree, which is a far worse trade than the one this
// adapter is making.
var secretNoiseExcludes = []string{
	`(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|go\.sum|Cargo\.lock|poetry\.lock|Gemfile\.lock|composer\.lock)$`,
}

// excludePatterns returns every pattern for one invocation: the shared set
// translated into anchored regular expressions, this adapter's lockfile
// addendum, and whatever the user asked for.
//
// The shared set is the reason `.git` is covered, and that coverage is not
// optional here. Unlike Opengrep, `trufflehog filesystem` walks the
// repository's own object store, and a secret found inside a packfile is
// reported at a path like .git/objects/pack/pack-<sha>.pack. That path is a
// fingerprint input and it churns on every gc and every fetch, so those
// findings would report themselves as fixed-and-reintroduced forever.
func excludePatterns(excludes scan.Excludes, user []string) []string {
	patterns := excludes.TruffleHogPatterns()
	patterns = append(patterns, secretNoiseExcludes...)
	return append(patterns, user...)
}

// writeExcludeFile writes patterns to a newline-separated file in a fresh
// temporary directory, returning its path along with a cleanup function.
//
// A new directory per call rather than one cached location, and never a path
// under the scan target. [Scanner] is documented as safe for concurrent use and
// [scan.Run] fans scanners out in parallel, so a shared mutable path would be a
// data race on the filesystem. Writing it into the tree being scanned would be
// worse than a race: a file of credential-shaped regexes dropped into the target
// gets found by this adapter, and by Opengrep's --no-git-ignore pass in the same
// run.
//
// The returned cleanup is always safe to call, including after an error. It must
// be deferred by the caller around the subprocess invocation rather than inside
// it — the file has to outlive cmd.Wait.
func writeExcludeFile(patterns []string) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "pindrop-trufflehog-exclude-")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating %s exclude directory: %w", Name, err)
	}

	cleanup = func() {
		if err := os.RemoveAll(dir); err != nil {
			slog.Debug("removing trufflehog exclude directory", "dir", dir, "error", err)
		}
	}

	path = filepath.Join(dir, "exclude-paths.txt")
	body := strings.Join(patterns, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("writing %s exclude file: %w", Name, err)
	}

	return path, cleanup, nil
}

// validateExcludes reports the first pattern that is not a valid regular
// expression.
//
// TruffleHog would reject a bad pattern itself, but it does so by exiting
// non-zero with a message that names neither the flag nor the pattern, leaving
// the user with a failed scan and nothing to act on. Compiling here means the
// error can say which of their patterns is wrong.
func validateExcludes(patterns []string) error {
	for _, p := range patterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("invalid --trufflehog-exclude-paths pattern %q: %w", p, err)
		}
	}
	return nil
}
