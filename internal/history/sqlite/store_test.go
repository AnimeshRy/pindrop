package sqlite_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/history/sqlite"
	"github.com/AnimeshRy/pindrop/internal/history/sqlite/sqlcgen"
	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

var baseTime = time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

func newStore(t *testing.T) *sqlite.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pindrop.db")
	store, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func repoRoot(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	return dir
}

type recordOpts struct {
	at        time.Time
	scanners  []string
	origin    string
	branch    string
	scopeHash string
	schema    int
}

func makeRecord(root string, opts recordOpts, findings ...scan.Finding) history.Record {
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
	return history.Record{
		Root: root,
		VCS:  history.RunVCS{Origin: opts.origin, Branch: opts.branch, Commit: "abc123"},
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

func put(t *testing.T, store *sqlite.Store, rec history.Record) history.Run {
	t.Helper()
	run, err := store.Put(context.Background(), rec)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return run
}

func finding(fp, scanner string) scan.Finding {
	return scan.Finding{
		Fingerprint: fp,
		Scanner:     scanner,
		RuleID:      "TEST",
		Category:    scan.CategoryVulnerability,
		Severity:    scan.SeverityHigh,
		Title:       fp,
		Location:    scan.Location{Path: "main.go", StartLine: 1},
	}
}

func statusIn(t *testing.T, store *sqlite.Store, id history.RepoID, fingerprint string) scan.Status {
	t.Helper()
	states, err := store.States(context.Background(), id, history.FindingQuery{})
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
	if first.Delta != (history.DeltaCounts{New: 2}) {
		t.Errorf("first run delta = %+v, want two new", first.Delta)
	}
	second := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour)}, vuln))
	if second.Delta != (history.DeltaCounts{StillOpen: 1, Fixed: 1}) {
		t.Errorf("second run delta = %+v, want one still open and one fixed", second.Delta)
	}
	third := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(2 * time.Hour)}, vuln, secret))
	if third.Delta != (history.DeltaCounts{StillOpen: 1, Regressed: 1}) {
		t.Errorf("third run delta = %+v, want one still open and one regressed", third.Delta)
	}
}

func TestPutScannerSubsetDoesNotMarkFindingsFixed(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")
	secret := finding("fp-secret", "trufflehog")
	secret.Category = scan.CategorySecret

	put(t, store, makeRecord(root, recordOpts{at: baseTime, scanners: []string{"trivy", "trufflehog"}}, vuln, secret))
	second := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour), scanners: []string{"trivy"}}, vuln))
	if second.Delta.Fixed != 0 {
		t.Errorf("delta.Fixed = %d, want 0", second.Delta.Fixed)
	}
}

func TestCorruptStateRebuildsSilently(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")
	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, vuln))

	// Simulate a broken lifecycle index by deleting all finding_states rows.
	db, err := sql.Open("sqlite", store.Path())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM finding_states WHERE repo_id = ?`, run.RepoID); err != nil {
		t.Fatalf("delete states: %v", err)
	}
	_ = db.Close()

	if err := store.Rebuild(context.Background(), run.RepoID); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if got := statusIn(t, store, run.RepoID, "fp-vuln"); got != scan.StatusNew {
		t.Errorf("status after rebuild = %q, want new", got)
	}
}

func TestRebuildPreservesUnreadableRunSummary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")

	second := put(t, store, makeRecord(root, recordOpts{at: baseTime}, vuln))
	secondRun, err := store.RunByID(ctx, second.RepoID, second.ID)
	if err != nil {
		t.Fatalf("RunByID: %v", err)
	}
	if secondRun.Counts.Total != 1 {
		t.Fatalf("counts before corruption = %+v, want one finding", secondRun.Counts)
	}

	db, err := sql.Open("sqlite", store.Path())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	q := sqlcgen.New(db)
	countsJSON, err := json.Marshal(secondRun.Counts)
	if err != nil {
		t.Fatalf("marshal counts: %v", err)
	}
	deltaJSON, err := json.Marshal(secondRun.Delta)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}
	if err := q.UpdateRunDerived(ctx, sqlcgen.UpdateRunDerivedParams{
		Document:   `{"schemaVersion": 99}`,
		Unreadable: 1,
		Problem:    "this run's record could not be decoded",
		RepoID:     string(second.RepoID),
		ID:         string(second.ID),
		Counts:     string(countsJSON),
		Delta:      string(deltaJSON),
	}); err != nil {
		t.Fatalf("corrupt run: %v", err)
	}
	_ = db.Close()

	if err := store.Rebuild(ctx, second.RepoID); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	got, err := store.RunByID(ctx, second.RepoID, second.ID)
	if err != nil {
		t.Fatalf("RunByID after rebuild: %v", err)
	}
	if got.Counts.Total != 1 {
		t.Errorf("counts after rebuild = %+v, want preserved total 1", got.Counts)
	}
	if got.Delta != secondRun.Delta {
		t.Errorf("delta after rebuild = %+v, want %+v", got.Delta, secondRun.Delta)
	}
}

func TestUnreadableScopeChangeBlocksFixedDetection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")

	put(t, store, makeRecord(root, recordOpts{at: baseTime, scopeHash: "scope-a"}, vuln))
	middle := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour), scopeHash: "scope-a"}, vuln))

	db, err := sql.Open("sqlite", store.Path())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	q := sqlcgen.New(db)
	if err := q.UpdateRunDerived(ctx, sqlcgen.UpdateRunDerivedParams{
		Document:   `{"schemaVersion": 99}`,
		Unreadable: 1,
		Problem:    "this run's record could not be decoded",
		RepoID:     string(middle.RepoID),
		ID:         string(middle.ID),
		Counts:     `{}`,
		Delta:      `{}`,
	}); err != nil {
		t.Fatalf("corrupt middle run: %v", err)
	}
	if _, err := db.Exec(`UPDATE runs SET scope_hash = ? WHERE repo_id = ? AND id = ?`,
		"scope-b", string(middle.RepoID), string(middle.ID)); err != nil {
		t.Fatalf("set middle scope: %v", err)
	}
	_ = db.Close()

	// Same scope as the first run, but finding gone — must not conclude fixed
	// because the unreadable middle run recorded a different exclusion set.
	third := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(2 * time.Hour), scopeHash: "scope-a"}))
	if third.Delta.Fixed != 0 {
		t.Errorf("third run delta.Fixed = %d, want 0 after unreadable scope change", third.Delta.Fixed)
	}
	if got := statusIn(t, store, third.RepoID, "fp-vuln"); got != scan.StatusOpen {
		t.Errorf("status after third run = %q, want open", got)
	}
}

func TestCorruptRunIsFlaggedNotDropped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	vuln := finding("fp-vuln", "trivy")

	put(t, store, makeRecord(root, recordOpts{at: baseTime}, vuln))
	second := put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Hour)}, vuln))

	db, err := sql.Open("sqlite", store.Path())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	q := sqlcgen.New(db)
	if err := q.UpdateRunDerived(ctx, sqlcgen.UpdateRunDerivedParams{
		Document:   `{"schemaVersion": 99}`,
		Unreadable: 1,
		Problem:    "this run's record could not be decoded",
		RepoID:     string(second.RepoID),
		ID:         string(second.ID),
		Counts:     `{}`,
		Delta:      `{}`,
	}); err != nil {
		t.Fatalf("corrupt run: %v", err)
	}
	_ = db.Close()

	if err := store.Rebuild(ctx, second.RepoID); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	runs, err := store.Runs(ctx, second.RepoID, history.RunQuery{})
	if err != nil {
		t.Fatalf("Runs: %v", err)
	}
	if len(runs) != 2 || !runs[0].Unreadable {
		t.Errorf("newest run = %+v, want unreadable", runs[0])
	}
	if _, err := store.Document(ctx, second.RepoID, second.ID); err == nil {
		t.Error("Document returned no error for unreadable run")
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
	if len(repos) != 1 || repos[0].Runs != runs {
		t.Errorf("repos = %+v, want 1 repo with %d runs", repos, runs)
	}
}

func TestPruneNeverDeletesTheNewestRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	var last history.Run
	for i := range 3 {
		last = put(t, store, makeRecord(root, recordOpts{at: baseTime.Add(time.Duration(i) * time.Hour)}, finding("fp", "trivy")))
	}
	deleted, err := store.Prune(ctx, last.RepoID, history.Retention{MaxRuns: 1})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}
	runs, err := store.Runs(ctx, last.RepoID, history.RunQuery{})
	if err != nil {
		t.Fatalf("Runs: %v", err)
	}
	if len(runs) == 0 || runs[0].ID != last.ID {
		t.Errorf("runs = %v, want newest %q", runs, last.ID)
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
	if _, err := store.RepoByID(ctx, run.RepoID); !errors.Is(err, history.ErrNotFound) {
		t.Errorf("RepoByID: err = %v, want ErrNotFound", err)
	}
}

func TestStoredDocumentIsReadable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, finding("fp", "trivy")))

	doc, err := store.Document(ctx, run.RepoID, run.ID)
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"schemaVersion", "findings", "runId", "repo", "status"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("document has no %q key", key)
		}
	}
}

func TestStoreRejectsTraversalIdentifiers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newStore(t)

	hostile := []string{"..", "../..", "../20240301T120000Z-abcdef12", "r_0123456789abcdef0123456789abcdef/../../../etc"}
	for _, id := range hostile {
		if _, err := store.RepoByID(ctx, history.RepoID(id)); !errors.Is(err, history.ErrNotFound) {
			t.Errorf("RepoByID(%q): err = %v, want ErrNotFound", id, err)
		}
	}
}

func TestStoreRejectsTraversalRunIdentifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, finding("fp", "trivy")))
	escape := history.RunID("../20240301T120000Z-abcdef12")
	if _, err := store.Document(ctx, run.RepoID, escape); !errors.Is(err, history.ErrNotFound) {
		t.Errorf("Document: err = %v, want ErrNotFound", err)
	}
}

func TestDefaultDBPathIsUnderPindropHome(t *testing.T) {
	t.Setenv("PINDROP_HOME", t.TempDir())
	path, err := history.DefaultDBPath()
	if err != nil {
		t.Fatalf("DefaultDBPath: %v", err)
	}
	if filepath.Base(path) != "pindrop.db" {
		t.Errorf("DefaultDBPath = %q, want pindrop.db", path)
	}
}
