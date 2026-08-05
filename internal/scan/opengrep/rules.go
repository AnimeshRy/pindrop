package opengrep

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

// bundledRules holds Pindrop's first-party ruleset.
//
// Embedded rather than read from disk so that a single `pindrop` binary is
// self-contained, which is the same property `//go:embed all:dist` gives the
// dashboard. Extracted at scan time because `opengrep --config` takes a
// filesystem path and has no way to accept rules on stdin.
//
// See rules/README.md for what is in here and why none of it was copied from an
// existing corpus.
//
//go:embed all:rules
var bundledRules embed.FS

// rulesRoot is the directory prefix inside bundledRules.
const rulesRoot = "rules"

// extractRules writes the embedded ruleset to a fresh temporary directory and
// returns its path along with a cleanup function.
//
// A new directory per call rather than one cached location: [Scanner] is
// documented as safe for concurrent use and [scan.Run] fans scanners out in
// parallel, so two scans sharing a mutable directory would be a data race on the
// filesystem. Ten small files cost nothing to write.
//
// The returned cleanup is always safe to call, including after an error.
func extractRules() (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "pindrop-opengrep-rules-")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating %s rules directory: %w", Name, err)
	}

	cleanup = func() {
		if err := os.RemoveAll(dir); err != nil {
			slog.Debug("removing opengrep rules directory", "dir", dir, "error", err)
		}
	}

	err = fs.WalkDir(bundledRules, rulesRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(rulesRoot, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)

		if entry.IsDir() {
			return os.MkdirAll(target, 0o750)
		}

		// The README is documentation for whoever edits the rules, not a rule.
		// Opengrep only reads .yml and .yaml from a config directory, so copying
		// it would be harmless — but writing only what the tool consumes keeps the
		// extracted directory an exact description of what ran.
		if filepath.Ext(rel) != ".yaml" && filepath.Ext(rel) != ".yml" {
			return nil
		}

		content, err := bundledRules.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o600)
	})
	if err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("extracting %s rules: %w", Name, err)
	}

	return dir, cleanup, nil
}
