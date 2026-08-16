package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/history/sqlite/sqlcgen"
	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
	_ "modernc.org/sqlite"
)

// Store is a [history.Store] backed by SQLite.
type Store struct {
	path string
	db   *sql.DB
	q    *sqlcgen.Queries

	mu    sync.Mutex
	locks map[history.RepoID]*sync.Mutex
}

// Open opens or creates the SQLite store at path.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("opening scan history: no database path given")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving the scan history database %q: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", toolpath.Display(filepath.Dir(abs)), err)
	}

	db, err := sql.Open("sqlite", abs+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening scan history database %s: %w", toolpath.Display(abs), err)
	}
	db.SetMaxOpenConns(1)

	if err := runMigrations(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(abs, history.DBFileMode); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = db.Close()
		return nil, fmt.Errorf("setting permissions on %s: %w", toolpath.Display(abs), err)
	}

	return &Store{
		path:  abs,
		db:    db,
		q:     sqlcgen.New(db),
		locks: map[history.RepoID]*sync.Mutex{},
	}, nil
}

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *Store) Path() string { return s.path }

func (s *Store) hold(id history.RepoID) func() {
	s.mu.Lock()
	m, ok := s.locks[id]
	if !ok {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	s.mu.Unlock()
	m.Lock()
	return m.Unlock
}

func (s *Store) Put(ctx context.Context, rec history.Record) (history.Run, error) {
	if err := ctx.Err(); err != nil {
		return history.Run{}, fmt.Errorf("recording scan history: %w", err)
	}
	if rec.Root == "" {
		return history.Run{}, errors.New("recording scan history: no scanned directory given")
	}

	root, err := history.CanonicalRoot(rec.Root)
	if err != nil {
		return history.Run{}, err
	}
	id := history.RepoIDFor(root)
	if existing, ok := s.detectMove(ctx, id, root, rec.VCS.Origin); ok {
		id = existing
	}

	release := s.hold(id)
	defer release()

	finished := rec.FinishedAt
	if finished.IsZero() {
		finished = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return history.Run{}, err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	fold, err := s.loadFold(ctx, q, id)
	if errors.Is(err, history.ErrNotFound) {
		fold = &history.Fold{Repo: history.Repo{ID: id}, States: map[string]history.FindingState{}}
	} else if err != nil {
		return history.Run{}, err
	}

	history.Identify(fold, root, rec.VCS.Origin)

	// Ensure the repo row exists before inserting runs that reference it.
	if fold.Repo.FirstRunAt.IsZero() {
		fold.Repo.FirstRunAt = finished
	}
	if fold.Repo.LastRunAt.IsZero() {
		fold.Repo.LastRunAt = finished
	}
	if err := q.UpsertRepo(ctx, repoToUpsert(fold.Repo)); err != nil {
		return history.Run{}, fmt.Errorf("recording repository: %w", err)
	}

	newest := history.RunID("")
	if n := len(fold.Runs); n > 0 {
		newest = fold.Runs[n-1].ID
	}
	runID, err := history.MintRunIDAfter(finished, newest)
	if err != nil {
		return history.Run{}, err
	}

	doc := history.DocumentFor(rec.Document, fold.Repo, rec.VCS, runID, finished)
	docJSON, err := history.EncodeDocumentJSON(doc)
	if err != nil {
		return history.Run{}, err
	}

	run, statuses, storedDoc := history.ApplyRunRecord(fold, history.RunRecord{
		ID:           runID,
		DocumentJSON: docJSON,
		StartedAt:    rec.StartedAt.UTC(),
		FinishedAt:   finished.UTC(),
		ScopeHash:    rec.ScopeHash,
	})
	if len(statuses) > 0 {
		storedDoc.Status = statuses
		docJSON, err = history.EncodeDocumentJSON(storedDoc)
		if err != nil {
			return history.Run{}, err
		}
	}

	if err := q.InsertRun(ctx, runToInsert(run, docJSON)); err != nil {
		return history.Run{}, fmt.Errorf("recording run: %w", err)
	}
	for _, f := range storedDoc.Findings {
		st := history.StatusOf(storedDoc, f)
		if err := q.InsertFinding(ctx, findingToInsert(id, runID, f, st)); err != nil {
			return history.Run{}, fmt.Errorf("recording finding: %w", err)
		}
	}
	if err := s.saveStates(ctx, q, id, fold.States); err != nil {
		return history.Run{}, err
	}
	fold.Repo.Runs = len(fold.Runs)
	fold.Repo.Open = countOpenFromMap(fold.States)
	if err := q.UpsertRepo(ctx, repoToUpsert(fold.Repo)); err != nil {
		return history.Run{}, fmt.Errorf("recording repository: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return history.Run{}, err
	}
	return run, nil
}

func (s *Store) saveStates(ctx context.Context, q *sqlcgen.Queries, id history.RepoID, states map[string]history.FindingState) error {
	for _, st := range states {
		if err := q.UpsertFindingState(ctx, stateToUpsert(id, st)); err != nil {
			return fmt.Errorf("recording finding state: %w", err)
		}
	}
	return nil
}

func (s *Store) loadFold(ctx context.Context, q *sqlcgen.Queries, id history.RepoID) (*history.Fold, error) {
	repoRow, err := q.GetRepo(ctx, string(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, history.ErrNotFound
		}
		return nil, err
	}
	runRows, err := q.ListRunsByRepo(ctx, string(id))
	if err != nil {
		return nil, err
	}
	states, err := s.loadStatesMap(ctx, q, id)
	if err != nil {
		return nil, err
	}

	fold := &history.Fold{Repo: repoFromRow(repoRow), States: states}
	for _, row := range runRows {
		run, err := runFromRow(row)
		if err != nil {
			return nil, err
		}
		fold.Runs = append(fold.Runs, run)
		fold.LastRun = run.ID
	}
	fold.Repo.Runs = len(fold.Runs)
	return fold, nil
}

func (s *Store) loadStatesMap(ctx context.Context, q *sqlcgen.Queries, id history.RepoID) (map[string]history.FindingState, error) {
	rows, err := q.ListFindingStates(ctx, string(id))
	if err != nil {
		return nil, err
	}
	states := make(map[string]history.FindingState, len(rows))
	for _, row := range rows {
		st := stateFromRow(row)
		states[st.Fingerprint] = st
	}
	return states, nil
}

func (s *Store) detectMove(ctx context.Context, id history.RepoID, root, origin string) (history.RepoID, bool) {
	if origin == "" {
		return "", false
	}
	if _, err := s.q.GetRepo(ctx, string(id)); err == nil {
		return "", false
	}
	ids, err := s.q.ListRepoIDs(ctx)
	if err != nil {
		return "", false
	}
	var found history.RepoID
	for _, other := range ids {
		if history.RepoID(other) == id {
			continue
		}
		repo, err := s.q.GetRepo(ctx, other)
		if err != nil {
			continue
		}
		if repo.Origin != origin || repo.Path == "" || repo.Path == root {
			continue
		}
		if _, err := os.Stat(repo.Path); err == nil {
			continue
		}
		if found != "" {
			return "", false
		}
		found = history.RepoID(other)
	}
	if found == "" {
		return "", false
	}
	slog.Debug("adopting scan history from a repository that moved", "repo", found, "to", root)
	return found, true
}

func (s *Store) Repos(ctx context.Context) ([]history.Repo, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing scan history: %w", err)
	}
	rows, err := s.q.ListRepos(ctx)
	if err != nil {
		return nil, err
	}
	repos := make([]history.Repo, 0, len(rows))
	for _, row := range rows {
		repo := s.enrichRepo(repoFromRow(row))
		repo.Runs = s.countRuns(ctx, repo.ID)
		repos = append(repos, repo)
	}
	return repos, nil
}

func (s *Store) countRuns(ctx context.Context, id history.RepoID) int {
	runs, err := s.q.ListRunsByRepo(ctx, string(id))
	if err != nil {
		return 0
	}
	return len(runs)
}

func (s *Store) enrichRepo(repo history.Repo) history.Repo {
	if repo.Path != "" {
		if _, err := os.Stat(repo.Path); err != nil {
			repo.Missing = true
		}
	}
	states, err := s.loadStatesMap(context.Background(), s.q, repo.ID)
	if err == nil {
		repo.Open = countOpenFromMap(states)
	}
	return repo
}

func countOpenFromMap(states map[string]history.FindingState) history.Counts {
	counts := history.Counts{BySeverity: map[scan.Severity]int{}, ByCategory: map[scan.Category]int{}}
	for _, st := range states {
		if !st.Status.Open() {
			continue
		}
		counts.Total++
		counts.BySeverity[st.Severity]++
		counts.ByCategory[st.Category]++
	}
	if len(counts.BySeverity) == 0 {
		counts.BySeverity = nil
	}
	if len(counts.ByCategory) == 0 {
		counts.ByCategory = nil
	}
	return counts
}

func (s *Store) RepoByID(ctx context.Context, id history.RepoID) (history.Repo, error) {
	if err := ctx.Err(); err != nil {
		return history.Repo{}, fmt.Errorf("reading scan history: %w", err)
	}
	if err := history.ValidateRepoID(id); err != nil {
		return history.Repo{}, err
	}
	row, err := s.q.GetRepo(ctx, string(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return history.Repo{}, fmt.Errorf("no scan history for repository %s: %w", id, history.ErrNotFound)
		}
		return history.Repo{}, err
	}
	repo := s.enrichRepo(repoFromRow(row))
	repo.Runs = s.countRuns(ctx, id)
	return repo, nil
}

func (s *Store) RepoByPath(ctx context.Context, path string) (history.Repo, error) {
	if err := ctx.Err(); err != nil {
		return history.Repo{}, fmt.Errorf("reading scan history: %w", err)
	}
	root, err := history.CanonicalRoot(path)
	if err != nil {
		return history.Repo{}, err
	}
	if repo, err := s.RepoByID(ctx, history.RepoIDFor(root)); err == nil {
		return repo, nil
	} else if !errors.Is(err, history.ErrNotFound) {
		return history.Repo{}, err
	}
	ids, err := s.q.ListRepoIDs(ctx)
	if err != nil {
		return history.Repo{}, err
	}
	for _, id := range ids {
		repo, err := s.RepoByID(ctx, history.RepoID(id))
		if err != nil {
			continue
		}
		if repo.Path == root || slices.Contains(repo.FormerPaths, root) {
			return repo, nil
		}
	}
	return history.Repo{}, fmt.Errorf("no scan history for %s — run: pindrop scan %s: %w",
		toolpath.Display(root), path, history.ErrNotFound)
}

func (s *Store) Runs(ctx context.Context, id history.RepoID, q history.RunQuery) ([]history.Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("reading scan history: %w", err)
	}
	if err := history.ValidateRepoID(id); err != nil {
		return nil, err
	}
	runs, err := s.listRuns(ctx, id)
	if err != nil {
		return nil, err
	}
	cutoff := len(runs)
	if q.Before != "" {
		cutoff = indexRunSlice(runs, q.Before)
		if cutoff < 0 {
			return nil, fmt.Errorf("run %s is not in this repository's history: %w", q.Before, history.ErrNotFound)
		}
	}
	out := make([]history.Run, 0, min(cutoff, 64))
	for i := cutoff - 1; i >= 0; i-- {
		run := runs[i]
		if !q.Matches(run) {
			continue
		}
		out = append(out, run)
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, nil
}

func indexRunSlice(runs []history.Run, id history.RunID) int {
	for i, r := range runs {
		if r.ID == id {
			return i
		}
	}
	return -1
}

func (s *Store) listRuns(ctx context.Context, id history.RepoID) ([]history.Run, error) {
	rows, err := s.q.ListRunsByRepo(ctx, string(id))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		if _, err := s.q.GetRepo(ctx, string(id)); errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no scan history for repository %s: %w", id, history.ErrNotFound)
		}
	}
	runs := make([]history.Run, 0, len(rows))
	for _, row := range rows {
		run, err := runFromRow(row)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func (s *Store) RunByID(ctx context.Context, id history.RepoID, run history.RunID) (history.Run, error) {
	if err := ctx.Err(); err != nil {
		return history.Run{}, fmt.Errorf("reading scan history: %w", err)
	}
	if err := history.ValidateRepoID(id); err != nil {
		return history.Run{}, err
	}
	if err := history.ValidateRunID(run); err != nil {
		return history.Run{}, err
	}
	row, err := s.q.GetRun(ctx, sqlcgen.GetRunParams{RepoID: string(id), ID: string(run)})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return history.Run{}, fmt.Errorf("run %s is not in this repository's history: %w", run, history.ErrNotFound)
		}
		return history.Run{}, err
	}
	return runFromRow(row)
}

func (s *Store) Document(ctx context.Context, id history.RepoID, run history.RunID) (report.Document, error) {
	if err := ctx.Err(); err != nil {
		return report.Document{}, fmt.Errorf("reading scan history: %w", err)
	}
	if err := history.ValidateRepoID(id); err != nil {
		return report.Document{}, err
	}
	if err := history.ValidateRunID(run); err != nil {
		return report.Document{}, err
	}
	row, err := s.q.GetRun(ctx, sqlcgen.GetRunParams{RepoID: string(id), ID: string(run)})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return report.Document{}, fmt.Errorf("run %s is not in this repository's history: %w", run, history.ErrNotFound)
		}
		return report.Document{}, err
	}
	if row.Unreadable != 0 {
		return report.Document{}, errors.New(row.Problem)
	}
	return report.DecodeDocument(bytes.NewReader([]byte(row.Document)))
}

func (s *Store) Findings(ctx context.Context, id history.RepoID, run history.RunID, q history.FindingQuery) ([]scan.Delta, error) {
	doc, err := s.Document(ctx, id, run)
	if err != nil {
		return nil, err
	}
	deltas := make([]scan.Delta, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		deltas = append(deltas, scan.Delta{Status: history.StatusOf(doc, f), Finding: f})
	}
	return history.Page(history.FilterDeltas(deltas, q), q), nil
}

func (s *Store) States(ctx context.Context, id history.RepoID, q history.FindingQuery) ([]history.FindingState, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("reading scan history: %w", err)
	}
	if err := history.ValidateRepoID(id); err != nil {
		return nil, err
	}
	statesMap, err := s.loadStatesMap(ctx, s.q, id)
	if err != nil {
		return nil, err
	}
	if len(statesMap) == 0 {
		if _, err := s.q.GetRepo(ctx, string(id)); errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no scan history for repository %s: %w", id, history.ErrNotFound)
		}
	}
	states := make([]history.FindingState, 0, len(statesMap))
	for _, st := range statesMap {
		if !q.MatchesState(st) {
			continue
		}
		states = append(states, st)
	}
	slices.SortFunc(states, func(a, b history.FindingState) int {
		if c := b.Severity.Rank() - a.Severity.Rank(); c != 0 {
			return c
		}
		if c := b.LastSeenAt.Compare(a.LastSeenAt); c != 0 {
			return c
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
	return history.Page(states, q), nil
}

func (s *Store) DiffRuns(ctx context.Context, id history.RepoID, req history.DiffRequest) (history.Diff, error) {
	if err := ctx.Err(); err != nil {
		return history.Diff{}, fmt.Errorf("reading scan history: %w", err)
	}
	if err := history.ValidateRepoID(id); err != nil {
		return history.Diff{}, err
	}
	runs, err := s.listRuns(ctx, id)
	if err != nil {
		return history.Diff{}, err
	}
	head, base, err := history.ResolveDiffRuns(runs, req)
	if err != nil {
		return history.Diff{}, err
	}
	headDoc, err := s.Document(ctx, id, head.ID)
	if err != nil {
		return history.Diff{}, err
	}
	diff := history.Diff{Head: head.ID}
	var baseFindings []scan.Finding
	if base != nil {
		baseDoc, err := s.Document(ctx, id, base.ID)
		if err != nil {
			return history.Diff{}, err
		}
		diff.Base = base.ID
		baseFindings = baseDoc.Findings
	}
	partitioned := scan.Diff(baseFindings, headDoc.Findings)
	for _, f := range partitioned.New {
		if headDoc.Status[f.Fingerprint] == scan.StatusRegressed {
			diff.Regressed = append(diff.Regressed, f)
			continue
		}
		diff.New = append(diff.New, f)
	}
	diff.StillOpen = partitioned.StillOpen
	ran := scannersThatRan(head.Scanners)
	sameExcludes := base == nil || base.ScopeHash == head.ScopeHash
	for _, f := range partitioned.Fixed {
		if sameExcludes && checkedBy(history.ReportersOf(f), ran) {
			diff.Fixed = append(diff.Fixed, f)
		}
	}
	diff.Counts = history.DeltaCounts{
		New: len(diff.New), StillOpen: len(diff.StillOpen), Fixed: len(diff.Fixed), Regressed: len(diff.Regressed),
	}
	return diff, nil
}

func scannersThatRan(scans []report.ScanSummary) map[string]bool {
	ran := make(map[string]bool, len(scans))
	for _, sc := range scans {
		if sc.Scanner != "" {
			ran[sc.Scanner] = true
		}
	}
	return ran
}

func checkedBy(reporters []string, ran map[string]bool) bool {
	for _, name := range reporters {
		if ran[name] {
			return true
		}
	}
	return false
}

func (s *Store) Rebuild(ctx context.Context, id history.RepoID) error {
	if err := history.ValidateRepoID(id); err != nil {
		return err
	}
	release := s.hold(id)
	defer release()
	return s.rebuild(ctx, id)
}

func (s *Store) rebuild(ctx context.Context, id history.RepoID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.rebuildTx(ctx, s.q.WithTx(tx), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) rebuildTx(ctx context.Context, q *sqlcgen.Queries, id history.RepoID) error {
	repoRow, err := q.GetRepo(ctx, string(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no scan history for repository %s: %w", id, history.ErrNotFound)
		}
		return err
	}
	runRows, err := q.ListRunsByRepo(ctx, string(id))
	if err != nil {
		return err
	}
	if err := q.DeleteFindingStatesByRepo(ctx, string(id)); err != nil {
		return err
	}

	fold := &history.Fold{
		Repo:   repoFromRow(repoRow),
		States: map[string]history.FindingState{},
	}
	for _, row := range runRows {
		rec := runRecordFromRow(row)
		run, statuses, doc := history.ApplyRunRecord(fold, rec)
		if run.Unreadable {
			stored, err := runFromRow(row)
			if err != nil {
				return err
			}
			// Rebuild cannot recompute summary fields from a corrupt document;
			// keep what was written before the file became unreadable.
			run.Tool = stored.Tool
			run.Scanners = stored.Scanners
			run.Counts = stored.Counts
			run.Delta = stored.Delta
			run.VCS = stored.VCS
			run.DurationMS = stored.DurationMS
		}
		docJSON := row.Document
		if len(statuses) > 0 {
			doc.Status = statuses
			encoded, err := history.EncodeDocumentJSON(doc)
			if err != nil {
				return err
			}
			docJSON = encoded
		}
		if err := q.UpdateRunDerived(ctx, sqlcgen.UpdateRunDerivedParams{
			PrevRunID:  string(run.PrevRun),
			Counts:     mustJSON(run.Counts),
			Delta:      mustJSON(run.Delta),
			Unreadable: boolToInt64(run.Unreadable),
			Problem:    run.Problem,
			Document:   docJSON,
			RepoID:     string(id),
			ID:         string(run.ID),
		}); err != nil {
			return err
		}
	}
	if err := s.saveStates(ctx, q, id, fold.States); err != nil {
		return err
	}
	fold.Repo.Runs = len(fold.Runs)
	fold.Repo.Open = countOpenFromMap(fold.States)
	if err := q.UpsertRepo(ctx, repoToUpsert(fold.Repo)); err != nil {
		return err
	}
	return nil
}

func (s *Store) Prune(ctx context.Context, id history.RepoID, p history.Retention) (int, error) {
	if err := history.ValidateRepoID(id); err != nil {
		return 0, err
	}
	release := s.hold(id)
	defer release()

	runs, err := s.listRuns(ctx, id)
	if err != nil {
		return 0, err
	}
	ids := make([]history.RunID, len(runs))
	for i, run := range runs {
		ids[i] = run.ID
	}
	doomed := history.Expired(ids, p, time.Now().UTC())
	if len(doomed) == 0 {
		return 0, nil
	}
	strIDs := make([]string, len(doomed))
	for i, run := range doomed {
		strIDs[i] = string(run)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)
	if err := q.DeleteRuns(ctx, sqlcgen.DeleteRunsParams{RepoID: string(id), Ids: strIDs}); err != nil {
		return 0, err
	}
	if err := s.rebuildTx(ctx, q, id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(doomed), nil
}

func (s *Store) Forget(ctx context.Context, id history.RepoID) error {
	if err := history.ValidateRepoID(id); err != nil {
		return err
	}
	release := s.hold(id)
	defer release()
	if err := s.q.DeleteRepo(ctx, string(id)); err != nil {
		return fmt.Errorf("deleting repository history: %w", err)
	}
	return nil
}

var _ history.Store = (*Store)(nil)
