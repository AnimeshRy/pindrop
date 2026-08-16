package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/history"
	sqlitestore "github.com/AnimeshRy/pindrop/internal/history/sqlite"
	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
	"github.com/AnimeshRy/pindrop/internal/vcs"
)

// recordHistory persists one completed scan.
//
// results must be UNFILTERED. Recording a --min-severity-narrowed set would
// make the next default scan report every dropped finding as newly
// reintroduced.
//
// A persistence failure is a warning, never a scan failure. `--fail-on` is
// about what was found; a scan that turned up forty criticals must not change
// its exit code because a home directory was read-only.
func recordHistory(
	ctx context.Context,
	results []scan.Result,
	target scan.Target,
	ran []scan.Scanner,
	started time.Time,
) {
	run, err := putHistory(ctx, results, target, ran, started)
	if err != nil {
		slog.Warn("could not record this scan in history", "error", err)
		fmt.Fprintf(os.Stderr, "Warning: this scan was not recorded in history: %v\n", err)
		return
	}

	if run.Delta.New == 0 && run.Delta.Fixed == 0 && run.Delta.Regressed == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", summarizeDelta(run))
}

// putHistory does the work recordHistory reports on.
func putHistory(
	ctx context.Context,
	results []scan.Result,
	target scan.Target,
	ran []scan.Scanner,
	started time.Time,
) (history.Run, error) {
	path, err := history.DefaultDBPath()
	if err != nil {
		return history.Run{}, err
	}

	store, err := sqlitestore.Open(path)
	if err != nil {
		return history.Run{}, err
	}
	defer func() { _ = store.Close() }()

	doc := report.NewDocument(results)

	// A scanner that ran and found nothing must still appear, or the next run
	// cannot tell "nothing to report" from "did not run" — which is the
	// difference between a finding being fixed and merely unobserved.
	doc.Scans = withSilentScanners(doc.Scans, ran, target.Path, started)

	rec := history.Record{
		Root:       target.Path,
		Document:   doc,
		StartedAt:  started,
		FinishedAt: time.Now(),
	}

	if info, err := vcs.Inspect(target.Path); err == nil {
		rec.Root = info.Root
		rec.VCS = history.RunVCS{
			Origin: info.Origin,
			Branch: info.Branch,
			Commit: info.Commit,
		}
	} else if !errors.Is(err, vcs.ErrNotRepo) {
		// Not fatal: a directory Pindrop cannot read git metadata for is still
		// worth recording, just without branch and commit.
		slog.Debug("could not read git metadata", "path", target.Path, "error", err)
	}

	// Computed after rec.Root is known, because the scanned path matters only
	// relative to the repository root.
	rec.ScopeHash = scopeHash(rec.Root, target)

	return store.Put(ctx, rec)
}

// withSilentScanners adds a zero-finding entry for every scanner that ran but
// reported nothing, so [history.Run.Scanners] is a complete record of what was
// actually checked.
func withSilentScanners(
	scans []report.ScanSummary,
	ran []scan.Scanner,
	targetPath string,
	started time.Time,
) []report.ScanSummary {
	seen := make(map[string]bool, len(scans))
	for _, s := range scans {
		seen[s.Scanner] = true
	}

	for _, s := range ran {
		if seen[s.Name()] {
			continue
		}
		scans = append(scans, report.ScanSummary{
			Scanner:   s.Name(),
			Target:    targetPath,
			StartedAt: started,
		})
	}
	return scans
}

// scopeHash digests everything that bounded what a run could report: the
// directory scanned, relative to the repository root, and the exclusion set.
//
// Both terms exist to stop a finding being called fixed when it merely could
// not have been seen.
//
// The exclusions are the obvious one — excluding a directory makes its findings
// vanish, and vanishing is not fixing. The scanned path is the subtle one. A
// repository's identity is its work-tree root, so `pindrop scan ./services/api`
// and `pindrop scan .` record against the same repository; without the path
// here, the narrower run would conclude that every finding outside services/api
// had been fixed.
//
// Patterns arrive sorted from [scan.Excludes.Merge], so the digest does not
// depend on the order they were written in a config file.
func scopeHash(root string, target scan.Target) string {
	h := sha256.New()

	rel, err := filepath.Rel(root, target.Path)
	if err != nil {
		// Not comparable to anything; treat the scope as unique rather than
		// as equal to some other run's.
		rel = target.Path
	}
	_, _ = h.Write([]byte("root\x1f" + filepath.ToSlash(rel) + "\x1e"))

	for _, d := range target.Excludes.Dirs {
		_, _ = h.Write([]byte("d\x1f" + d + "\x1e"))
	}
	for _, f := range target.Excludes.Files {
		_, _ = h.Write([]byte("f\x1f" + f + "\x1e"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// summarizeDelta describes what changed since the previous scan of this repo.
//
// Deliberately says "no longer detected" rather than "fixed" for the resolved
// count. A scanner ceasing to report something is a weaker claim than a fix,
// and overstating it is how a security tool teaches people to distrust it.
func summarizeDelta(run history.Run) string {
	parts := make([]string, 0, 3)
	if run.Delta.New > 0 {
		parts = append(parts, fmt.Sprintf("%d new", run.Delta.New))
	}
	if run.Delta.Regressed > 0 {
		parts = append(parts, fmt.Sprintf("%d returned", run.Delta.Regressed))
	}
	if run.Delta.Fixed > 0 {
		parts = append(parts, fmt.Sprintf("%d no longer detected", run.Delta.Fixed))
	}

	summary := "Since the previous scan: " + strings.Join(parts, ", ")
	if run.PrevRun == "" {
		summary = fmt.Sprintf("First recorded scan of this repository: %d findings", run.Counts.Total)
	}
	return summary + "\n  Browse history with `pindrop serve`."
}

// openHistory opens the scan-history store at its default location.
func openHistory() (history.Store, error) {
	path, err := history.DefaultDBPath()
	if err != nil {
		return nil, fmt.Errorf("locating scan history: %w", err)
	}

	store, err := sqlitestore.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening scan history at %s: %w", toolpath.Display(path), err)
	}
	return store, nil
}
