package history

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// baseTime is a fixed instant so that run identifiers, and therefore commit
// order, are deterministic across a test's runs.
var baseTime = time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

// newStore opens a store in a temporary directory.
func newStore(t *testing.T) *JSONStore {
	t.Helper()
	store, err := OpenJSON(t.TempDir())
	if err != nil {
		t.Fatalf("OpenJSON: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// repoRoot creates a directory to stand in for a scanned checkout.
func repoRoot(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	return dir
}

// recordOpts is the varying part of a test record.
type recordOpts struct {
	at        time.Time
	scanners  []string
	origin    string
	branch    string
	scopeHash string
	schema    int
}

// makeRecord assembles a Record the way the CLI would.
func makeRecord(root string, opts recordOpts, findings ...scan.Finding) Record {
	if opts.at.IsZero() {
		opts.at = baseTime
	}
	if len(opts.scanners) == 0 {
		opts.scanners = []string{"trivy"}
	}
	if opts.schema == 0 {
		opts.schema = report.DocumentSchemaVersion
	}

	scans := make([]report.ScanSummary, 0, len(opts.scanners))
	for _, name := range opts.scanners {
		scans = append(scans, report.ScanSummary{
			Scanner:   name,
			Target:    root,
			StartedAt: opts.at,
			Findings:  len(findings),
		})
	}
	return Record{
		Root: root,
		VCS:  RunVCS{Origin: opts.origin, Branch: opts.branch, Commit: "abc123"},
		Document: report.Document{
			SchemaVersion: opts.schema,
			GeneratedAt:   opts.at,
			Tool:          report.Tool{Name: "pindrop", Version: "test"},
			Scans:         scans,
			Findings:      findings,
		},
		StartedAt:  opts.at,
		FinishedAt: opts.at,
		ScopeHash:  opts.scopeHash,
	}
}

// put records a scan and fails the test if it does not.
func put(t *testing.T, store *JSONStore, rec Record) Run {
	t.Helper()
	run, err := store.Put(context.Background(), rec)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return run
}

// statusIn reads one fingerprint's status out of the lifecycle index.
func statusIn(t *testing.T, store *JSONStore, id RepoID, fingerprint string) scan.Status {
	t.Helper()
	states, err := store.States(context.Background(), id, FindingQuery{})
	if err != nil {
		t.Fatalf("States: %v", err)
	}
	for _, st := range states {
		if st.Fingerprint == fingerprint {
			return st.Status
		}
	}
	t.Fatalf("fingerprint %q is not in the lifecycle index", fingerprint)
	return ""
}

func TestPutTracksLifecycleAcrossRuns(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln, secret := finding("fp-vuln", "trivy"), finding("fp-secret", "trivy")

	first := put(t, store, makeRecord(root, recordOpts{at: baseTime}, vuln, secret))
	if first.Delta != (DeltaCounts{New: 2}) {
		t.Errorf("first run delta = %+v, want two new", first.Delta)
	}
	if first.PrevRun != "" {
		t.Errorf("first run prevRun = %q, want empty", first.PrevRun)
	}

	second := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour)}, vuln))
	if second.Delta != (DeltaCounts{StillOpen: 1, Fixed: 1}) {
		t.Errorf("second run delta = %+v, want one still open and one fixed", second.Delta)
	}
	if second.PrevRun != first.ID {
		t.Errorf("second run prevRun = %q, want %q", second.PrevRun, first.ID)
	}
	if got := statusIn(t, store, second.RepoID, "fp-secret"); got != scan.StatusFixed {
		t.Errorf("secret status = %q, want %q", got, scan.StatusFixed)
	}

	third := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(2 * time.Hour)}, vuln, secret))
	if third.Delta != (DeltaCounts{StillOpen: 1, Regressed: 1}) {
		t.Errorf("third run delta = %+v, want one still open and one regressed", third.Delta)
	}
	if got := statusIn(t, store, third.RepoID, "fp-secret"); got != scan.StatusRegressed {
		t.Errorf("secret status = %q, want %q", got, scan.StatusRegressed)
	}

	repo, err := store.RepoByID(context.Background(), third.RepoID)
	if err != nil {
		t.Fatalf("RepoByID: %v", err)
	}
	if repo.Runs != 3 || repo.LastRun != third.ID {
		t.Errorf("repo = %d runs ending %q, want 3 ending %q", repo.Runs, repo.LastRun, third.ID)
	}
	if repo.Open.Total != 2 {
		t.Errorf("open total = %d, want 2", repo.Open.Total)
	}
}

func TestPutScannerSubsetDoesNotMarkFindingsFixed(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")
	secret := finding("fp-secret", "trufflehog")
	secret.Category = scan.CategorySecret

	first := put(t, store, makeRecord(root,
		recordOpts{at: baseTime, scanners: []string{"trivy", "trufflehog"}}, vuln, secret))

	// The scan a user runs as `pindrop scan --scanners vuln`: the secret is
	// absent because nobody looked for it.
	second := put(t, store, makeRecord(root,
		recordOpts{at: baseTime.Add(time.Hour), scanners: []string{"trivy"}}, vuln))

	if second.Delta.Fixed != 0 {
		t.Errorf("delta.Fixed = %d, want 0 — trufflehog never ran, so nothing it reported can be fixed", second.Delta.Fixed)
	}
	if got := statusIn(t, store, first.RepoID, "fp-secret"); got != scan.StatusNew {
		t.Errorf("secret status = %q, want it left at %q", got, scan.StatusNew)
	}
}

func TestPutChangedExcludesDoesNotMarkFindingsFixed(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	root := repoRoot(t, "proj")
	kept, excluded := finding("fp-kept", "trivy"), finding("fp-excluded", "trivy")

	put(t, store, makeRecord(root, recordOpts{at: baseTime, scopeHash: "sha256:aaa"}, kept, excluded))
	second := put(t, store, makeRecord(root,
		recordOpts{at: baseTime.Add(time.Hour), scopeHash: "sha256:bbb"}, kept))

	if second.Delta.Fixed != 0 {
		t.Errorf("delta.Fixed = %d, want 0 — a finding hidden by a new exclusion was not fixed", second.Delta.Fixed)
	}
	if got := statusIn(t, store, second.RepoID, "fp-excluded"); got != scan.StatusNew {
		t.Errorf("excluded finding status = %q, want it left at %q", got, scan.StatusNew)
	}

	// With the exclusions stable again, the same absence is a real fix.
	third := put(t, store, makeRecord(root,
		recordOpts{at: baseTime.Add(2 * time.Hour), scopeHash: "sha256:bbb"}, kept))
	if third.Delta.Fixed != 1 {
		t.Errorf("delta.Fixed = %d, want 1 once the exclusion set is stable", third.Delta.Fixed)
	}
}

func TestCorruptStateFileRebuildsSilently(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")

	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, vuln))
	statePath := filepath.Join(repoDir(store.Dir(), run.RepoID), stateFileName)
	if err := os.WriteFile(statePath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupting %s: %v", statePath, err)
	}

	if got := statusIn(t, store, run.RepoID, "fp-vuln"); got != scan.StatusNew {
		t.Errorf("status after rebuild = %q, want %q", got, scan.StatusNew)
	}

	// A later scan must land on the rebuilt index, not start from nothing.
	second := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour)}, vuln))
	if second.Delta != (DeltaCounts{StillOpen: 1}) {
		t.Errorf("delta = %+v, want one still open — a rebuilt index must not report old findings as new", second.Delta)
	}
}

func TestCorruptRunFileIsFlaggedNotDropped(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")

	first := put(t, store, makeRecord(root, recordOpts{at: baseTime}, vuln))
	second := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour)}, vuln))

	// A run file written by a newer pindrop, or damaged on disk, discovered when
	// the derived files are regenerated from it.
	path := runPath(store.Dir(), second.RepoID, second.ID)
	if err := os.WriteFile(path, []byte(`{"schemaVersion": 99}`), 0o600); err != nil {
		t.Fatalf("corrupting %s: %v", path, err)
	}
	if err := store.Rebuild(ctx, second.RepoID); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}

	runs, err := store.Runs(ctx, first.RepoID, RunQuery{})
	if err != nil {
		t.Fatalf("Runs: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("Runs returned %d runs, want 2 — an unreadable run must still be listed", len(runs))
	}
	if !runs[0].Unreadable || runs[0].Problem == "" {
		t.Errorf("newest run = %+v, want it flagged unreadable with a problem", runs[0])
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the unreadable run file was removed: %v", err)
	}

	// Its findings are unknown, not fixed.
	if got := statusIn(t, store, first.RepoID, "fp-vuln"); got != scan.StatusNew {
		t.Errorf("status = %q, want it left at %q rather than concluded fixed", got, scan.StatusNew)
	}
	if _, err := store.Document(ctx, first.RepoID, second.ID); err == nil {
		t.Error("Document returned no error for an unreadable run")
	}
}

func TestPutIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	root := repoRoot(t, "proj")
	const runs = 8

	var wg sync.WaitGroup
	errs := make([]error, runs)
	for i := range runs {
		wg.Go(func() {
			_, err := store.Put(context.Background(), makeRecord(root,
				recordOpts{at: baseTime.Add(time.Duration(i) * time.Minute)},
				finding("fp-vuln", "trivy")))
			errs[i] = err
		})
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	repos, err := store.Repos(context.Background())
	if err != nil {
		t.Fatalf("Repos: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("Repos returned %d repositories, want 1", len(repos))
	}
	if repos[0].Runs != runs {
		t.Errorf("recorded %d runs, want %d — concurrent puts must not overwrite each other", repos[0].Runs, runs)
	}
}

func TestPutIngestsAVersion1Document(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")

	run := put(t, store, makeRecord(root, recordOpts{at: baseTime, schema: 1}, finding("fp-vuln", "trivy")))

	doc, err := store.Document(ctx, run.RepoID, run.ID)
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if doc.SchemaVersion != report.DocumentSchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", doc.SchemaVersion, report.DocumentSchemaVersion)
	}
	if doc.RunID != string(run.ID) || doc.Repo == nil || doc.Repo.ID != string(run.RepoID) {
		t.Errorf("document identity = %+v, want run %q and repo %q", doc.Repo, run.ID, run.RepoID)
	}
	if len(doc.Status) != 1 || doc.Status["fp-vuln"] != scan.StatusNew {
		t.Errorf("status = %v, want fp-vuln new — a v1 document gains lifecycle state on ingest", doc.Status)
	}
}

func TestPutReplaysARunLeftBehindByACrash(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	first, second := finding("fp-first", "trivy"), finding("fp-second", "trivy")

	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, first))

	// A Put that wrote its run file and died before its index.
	orphan := RunID("20240301T130000Z-abcdef12")
	rec := makeRecord(root, recordOpts{at: baseTime.Add(time.Hour)}, first, second)
	doc := documentFor(rec.Document, Repo{ID: run.RepoID, Name: "proj", Path: root}, rec.VCS, orphan, rec.FinishedAt)
	if err := writeJSONAtomic(runPath(store.Dir(), run.RepoID, orphan), runFile{
		Document: doc,
		History:  runMeta{RepoID: run.RepoID, StartedAt: rec.StartedAt, FinishedAt: rec.FinishedAt},
	}); err != nil {
		t.Fatalf("writing the orphaned run: %v", err)
	}

	third := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(2 * time.Hour)}, first, second))
	if third.Delta != (DeltaCounts{StillOpen: 2}) {
		t.Errorf("delta = %+v, want two still open — the orphaned run must be replayed first", third.Delta)
	}
	if third.PrevRun != orphan {
		t.Errorf("prevRun = %q, want the orphaned run %q", third.PrevRun, orphan)
	}

	runs, err := store.Runs(ctx, run.RepoID, RunQuery{})
	if err != nil {
		t.Fatalf("Runs: %v", err)
	}
	if len(runs) != 3 {
		t.Errorf("Runs returned %d runs, want 3", len(runs))
	}
}

func TestPutAdoptsHistoryOnlyWhenTheOldPathIsGone(t *testing.T) {
	t.Parallel()

	t.Run("old path gone adopts", func(t *testing.T) {
		t.Parallel()

		store := newStore(t)
		origin := "github.com/owner/repo"
		before := repoRoot(t, "before")
		after := repoRoot(t, "after")

		first := put(t, store, makeRecord(before, recordOpts{at: baseTime, origin: origin}, finding("fp", "trivy")))
		if err := os.RemoveAll(before); err != nil {
			t.Fatalf("removing %s: %v", before, err)
		}

		second := put(t, store, makeRecord(after,
			recordOpts{at: baseTime.Add(time.Hour), origin: origin}, finding("fp", "trivy")))
		if second.RepoID != first.RepoID {
			t.Fatalf("repo id = %q, want the moved repository's %q", second.RepoID, first.RepoID)
		}

		repo, err := store.RepoByID(context.Background(), first.RepoID)
		if err != nil {
			t.Fatalf("RepoByID: %v", err)
		}
		if len(repo.FormerPaths) != 1 {
			t.Errorf("formerPaths = %v, want one entry", repo.FormerPaths)
		}
		if repo.Runs != 2 {
			t.Errorf("runs = %d, want 2", repo.Runs)
		}
	})

	t.Run("old path present stays distinct", func(t *testing.T) {
		t.Parallel()

		store := newStore(t)
		origin := "github.com/owner/repo"
		main := repoRoot(t, "main")
		worktree := repoRoot(t, "worktree")

		first := put(t, store, makeRecord(main, recordOpts{at: baseTime, origin: origin}, finding("fp", "trivy")))
		second := put(t, store, makeRecord(worktree,
			recordOpts{at: baseTime.Add(time.Hour), origin: origin}, finding("fp", "trivy")))

		if second.RepoID == first.RepoID {
			t.Error("two live checkouts of one repository were merged; a branch switch would report a wave of fixes")
		}
		repos, err := store.Repos(context.Background())
		if err != nil {
			t.Fatalf("Repos: %v", err)
		}
		if len(repos) != 2 {
			t.Errorf("Repos returned %d repositories, want 2", len(repos))
		}
	})
}

func TestReposWithTheSameBasenameStayDistinct(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	one := filepath.Join(repoRoot(t, "a"), "proj")
	two := filepath.Join(repoRoot(t, "b"), "proj")
	for _, dir := range []string{one, two} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("creating %s: %v", dir, err)
		}
	}

	first := put(t, store, makeRecord(one, recordOpts{at: baseTime}, finding("fp", "trivy")))
	second := put(t, store, makeRecord(two, recordOpts{at: baseTime}, finding("fp", "trivy")))

	if first.RepoID == second.RepoID {
		t.Fatalf("both directories got repo id %q; identity is the path, not the basename", first.RepoID)
	}
	repos, err := store.Repos(context.Background())
	if err != nil {
		t.Fatalf("Repos: %v", err)
	}
	if len(repos) != 2 {
		t.Errorf("Repos returned %d repositories, want 2", len(repos))
	}
}

func TestPruneNeverDeletesTheNewestRun(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tests := []struct {
		name      string
		retention Retention
		want      int
	}{
		{name: "by count", retention: Retention{MaxRuns: 1}, want: 2},
		{name: "by age", retention: Retention{MaxAge: time.Nanosecond}, want: 2},
		{name: "unbounded keeps everything", retention: Retention{}, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newStore(t)
			root := repoRoot(t, "proj")
			var last Run
			for i := range 3 {
				last = put(t, store, makeRecord(root,
					recordOpts{at: baseTime.Add(time.Duration(i) * time.Hour)}, finding("fp", "trivy")))
			}

			deleted, err := store.Prune(ctx, last.RepoID, tt.retention)
			if err != nil {
				t.Fatalf("Prune: %v", err)
			}
			if deleted != tt.want {
				t.Errorf("deleted = %d, want %d", deleted, tt.want)
			}

			runs, err := store.Runs(ctx, last.RepoID, RunQuery{})
			if err != nil {
				t.Fatalf("Runs: %v", err)
			}
			if len(runs) == 0 {
				t.Fatal("Prune left no runs at all")
			}
			if runs[0].ID != last.ID {
				t.Errorf("newest run = %q, want %q", runs[0].ID, last.ID)
			}
		})
	}
}

func TestDiffRuns(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	kept, gone, back := finding("fp-kept", "trivy"), finding("fp-gone", "trivy"), finding("fp-back", "trivy")

	put(t, store, makeRecord(root, recordOpts{at: baseTime}, kept, gone, back))
	put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour)}, kept))
	head := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(2 * time.Hour)}, kept, back))

	diff, err := store.DiffRuns(ctx, head.RepoID, DiffRequest{})
	if err != nil {
		t.Fatalf("DiffRuns: %v", err)
	}
	if diff.Head != head.ID {
		t.Errorf("head = %q, want %q", diff.Head, head.ID)
	}
	if diff.Counts != (DeltaCounts{StillOpen: 1, Regressed: 1}) {
		t.Errorf("counts = %+v, want one still open and one regressed", diff.Counts)
	}
	if len(diff.Regressed) != 1 || diff.Regressed[0].Fingerprint != "fp-back" {
		t.Errorf("regressed = %v, want fp-back", diff.Regressed)
	}
	if len(diff.New) != 0 {
		t.Errorf("new = %v, want none — a returning finding is regressed, not new", diff.New)
	}
}

func TestDiffRunsWillNotCallAFindingFixedThatNobodyLookedFor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")
	secret := finding("fp-secret", "trufflehog")

	base := put(t, store, makeRecord(root,
		recordOpts{at: baseTime, scanners: []string{"trivy", "trufflehog"}}, vuln, secret))
	head := put(t, store, makeRecord(root,
		recordOpts{at: baseTime.Add(time.Hour), scanners: []string{"trivy"}}, vuln))

	diff, err := store.DiffRuns(ctx, head.RepoID, DiffRequest{Base: base.ID, Head: head.ID})
	if err != nil {
		t.Fatalf("DiffRuns: %v", err)
	}
	if len(diff.Fixed) != 0 {
		t.Errorf("fixed = %v, want none — trufflehog did not run in the head run", diff.Fixed)
	}
}

func TestFindingsPairsStatusesWithFindings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	high := finding("fp-high", "trivy")
	low := finding("fp-low", "trivy")
	low.Severity = scan.SeverityLow

	put(t, store, makeRecord(root, recordOpts{at: baseTime}, high))
	run := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour)}, high, low))

	deltas, err := store.Findings(ctx, run.RepoID, run.ID, FindingQuery{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(deltas) != 2 {
		t.Fatalf("Findings returned %d entries, want 2", len(deltas))
	}
	got := map[string]scan.Status{}
	for _, d := range deltas {
		got[d.Finding.Fingerprint] = d.Status
	}
	if got["fp-high"] != scan.StatusOpen || got["fp-low"] != scan.StatusNew {
		t.Errorf("statuses = %v, want fp-high open and fp-low new", got)
	}

	filtered, err := store.Findings(ctx, run.RepoID, run.ID, FindingQuery{
		Severity: []scan.Severity{scan.SeverityLow},
	})
	if err != nil {
		t.Fatalf("Findings filtered: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Finding.Fingerprint != "fp-low" {
		t.Errorf("filtered = %v, want only fp-low", filtered)
	}
}

func TestRunsQueryFilters(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")

	first := put(t, store, makeRecord(root, recordOpts{at: baseTime, branch: "main"}, finding("fp", "trivy")))
	second := put(t, store, makeRecord(root,
		recordOpts{at: baseTime.Add(time.Hour), branch: "feature"}, finding("fp", "trivy")))
	third := put(t, store, makeRecord(root,
		recordOpts{at: baseTime.Add(2 * time.Hour), branch: "main"}, finding("fp", "trivy")))

	byBranch, err := store.Runs(ctx, first.RepoID, RunQuery{Branch: "main"})
	if err != nil {
		t.Fatalf("Runs: %v", err)
	}
	if len(byBranch) != 2 || byBranch[0].ID != third.ID {
		t.Errorf("branch filter returned %d runs starting %v, want 2 starting %q", len(byBranch), runIDs(byBranch), third.ID)
	}

	before, err := store.Runs(ctx, first.RepoID, RunQuery{Before: second.ID})
	if err != nil {
		t.Fatalf("Runs before: %v", err)
	}
	if len(before) != 1 || before[0].ID != first.ID {
		t.Errorf("before filter returned %v, want only %q", runIDs(before), first.ID)
	}

	limited, err := store.Runs(ctx, first.RepoID, RunQuery{Limit: 1})
	if err != nil {
		t.Fatalf("Runs limit: %v", err)
	}
	if len(limited) != 1 || limited[0].ID != third.ID {
		t.Errorf("limit returned %v, want only the newest %q", runIDs(limited), third.ID)
	}
}

// runIDs projects runs down to their identifiers, for failure messages.
func runIDs(runs []Run) []RunID {
	ids := make([]RunID, 0, len(runs))
	for _, r := range runs {
		ids = append(ids, r.ID)
	}
	return ids
}

func TestRepoByPathFindsTheWorkTreeAndFormerPaths(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	nested := filepath.Join(root, "internal")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("creating %s: %v", nested, err)
	}

	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, finding("fp", "trivy")))

	repo, err := store.RepoByPath(ctx, root)
	if err != nil {
		t.Fatalf("RepoByPath: %v", err)
	}
	if repo.ID != run.RepoID {
		t.Errorf("repo id = %q, want %q", repo.ID, run.RepoID)
	}

	if _, err := store.RepoByPath(ctx, filepath.Join(root, "nowhere")); !errors.Is(err, ErrNotFound) {
		t.Errorf("RepoByPath for an unscanned directory: err = %v, want ErrNotFound", err)
	}
}

func TestRepoReportsAMissingCheckout(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	root := repoRoot(t, "proj")
	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, finding("fp", "trivy")))
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("removing %s: %v", root, err)
	}

	repo, err := store.RepoByID(context.Background(), run.RepoID)
	if err != nil {
		t.Fatalf("RepoByID: %v", err)
	}
	if !repo.Missing {
		t.Error("repo.Missing = false, want true once the checkout is gone")
	}
}

func TestForgetRemovesEverything(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, finding("fp", "trivy")))

	if err := store.Forget(ctx, run.RepoID); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if _, err := store.RepoByID(ctx, run.RepoID); !errors.Is(err, ErrNotFound) {
		t.Errorf("RepoByID after Forget: err = %v, want ErrNotFound", err)
	}
	repos, err := store.Repos(ctx)
	if err != nil {
		t.Fatalf("Repos: %v", err)
	}
	if len(repos) != 0 {
		t.Errorf("Repos returned %d repositories, want 0", len(repos))
	}
}

func TestRunFileIsAReadableReportDocument(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	root := repoRoot(t, "proj")
	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, finding("fp", "trivy")))

	path := runPath(store.Dir(), run.RepoID, run.ID)
	// #nosec G304 -- a path this test just wrote.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	for _, key := range []string{"schemaVersion", "findings", "runId", "repo", "status", "history"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("run file has no %q key; `pindrop serve --results` reads this file as a report", key)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != fileMode {
		t.Errorf("run file mode = %v, want %v — findings are not world-readable", perm, fileMode)
	}
}

func TestDefaultDirIsUnderPindropHome(t *testing.T) {
	t.Setenv("PINDROP_HOME", t.TempDir())

	dir, err := DefaultDir()
	if err != nil {
		t.Fatalf("DefaultDir: %v", err)
	}
	if filepath.Base(dir) != "scans" {
		t.Errorf("DefaultDir = %q, want it to end in scans", dir)
	}
}
