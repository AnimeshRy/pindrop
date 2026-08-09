package history

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

// Repos lists every repository with history, most recently scanned first.
//
// This is one ReadDir plus one small file open per repository, with no index in
// between. That is the reason there is no index: two users, or two shells,
// scanning different repositories at the same time touch no shared file, and
// there is no cached list that can be wrong.
func (s *JSONStore) Repos(ctx context.Context) ([]Repo, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing scan history: %w", err)
	}

	ids := s.repoIDs()
	repos := make([]Repo, 0, len(ids))
	for _, id := range ids {
		repo, err := s.repo(id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // a directory with no runs and no repo.json is not a repository
			}
			return nil, err
		}
		repos = append(repos, repo)
	}

	slices.SortFunc(repos, func(a, b Repo) int {
		if c := b.LastRunAt.Compare(a.LastRunAt); c != 0 {
			return c
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	return repos, nil
}

// RepoByID returns one repository.
func (s *JSONStore) RepoByID(ctx context.Context, id RepoID) (Repo, error) {
	if err := ctx.Err(); err != nil {
		return Repo{}, fmt.Errorf("reading scan history: %w", err)
	}
	if err := validateRepoID(id); err != nil {
		return Repo{}, err
	}
	return s.repo(id)
}

// RepoByPath returns the repository a directory belongs to.
//
// The path is resolved exactly as [Store.Put] resolves it, so a subdirectory of
// a work tree finds the repository rooted at the work tree. A path that matches
// nothing is then looked for among recorded former paths, so that asking about
// a directory a repository has since moved out of still finds its history.
func (s *JSONStore) RepoByPath(ctx context.Context, path string) (Repo, error) {
	if err := ctx.Err(); err != nil {
		return Repo{}, fmt.Errorf("reading scan history: %w", err)
	}
	root, err := canonicalRoot(path)
	if err != nil {
		return Repo{}, err
	}

	if repo, err := s.repo(repoIDFor(root)); err == nil {
		return repo, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Repo{}, err
	}

	for _, id := range s.repoIDs() {
		rf, ok := loadRepoFile(s.dir, id)
		if !ok {
			continue
		}
		if rf.Repo.Path == root || slices.Contains(rf.Repo.FormerPaths, root) {
			return s.repo(id)
		}
	}
	return Repo{}, fmt.Errorf("no scan history for %s — run: pindrop scan %s: %w",
		toolpath.Display(root), path, ErrNotFound)
}

// repo loads one repository summary, repairing repo.json in memory when it is
// missing or corrupt.
//
// The repair is not written back, because a read must not need a lock: the run
// files are the truth, and the next Put — or an explicit [Store.Rebuild] —
// persists the corrected version.
func (s *JSONStore) repo(id RepoID) (Repo, error) {
	rf, err := s.repoFileFor(id)
	if err != nil {
		return Repo{}, err
	}
	repo := rf.Repo
	if repo.Path != "" {
		if _, err := os.Stat(repo.Path); err != nil {
			// The history is still worth showing; a dashboard just needs to say
			// why no new runs are arriving.
			repo.Missing = true
		}
	}
	return repo, nil
}

// repoFileFor loads repo.json, or reconstructs it from the run files.
//
// The cached run list is checked against the directory before it is trusted, so
// a read after a crash — or after a run file was restored from a backup — sees
// the runs that are actually there rather than the ones the last completed Put
// knew about.
func (s *JSONStore) repoFileFor(id RepoID) (*repoFile, error) {
	runs, err := listRuns(s.dir, id)
	if err != nil {
		return nil, err
	}
	if rf, ok := loadRepoFile(s.dir, id); ok && agrees(rf, runs) {
		return rf, nil
	}
	if len(runs) == 0 {
		if rf, ok := loadRepoFile(s.dir, id); ok {
			return rf, nil
		}
		return nil, fmt.Errorf("no scan history for repository %s: %w", id, ErrNotFound)
	}
	rf, _ := s.rebuildLocked(id, runs)
	return rf, nil
}

// agrees reports whether a cached run list matches the run files on disk. The
// comparison is length plus newest ID, which is enough to catch both an
// interrupted Put and a file that appeared behind the store's back, without
// opening anything.
func agrees(rf *repoFile, runs []RunID) bool {
	if len(rf.Runs) != len(runs) {
		return false
	}
	if len(runs) == 0 {
		return true
	}
	return rf.Runs[len(rf.Runs)-1].ID == runs[len(runs)-1]
}

// stateFor loads the lifecycle index, rebuilding it in memory when it is
// missing, corrupt, or behind the run files. Recovery is silent by design: the
// file is fully derived, and failing a read because a cache is broken would
// strand a user with history they cannot see.
func (s *JSONStore) stateFor(id RepoID) (*stateFile, error) {
	runs, err := listRuns(s.dir, id)
	if err != nil {
		return nil, err
	}
	newest := RunID("")
	if len(runs) > 0 {
		newest = runs[len(runs)-1]
	}

	if sf, ok := loadStateFile(s.dir, id); ok && sf.LastRun == newest {
		return sf, nil
	}
	if len(runs) == 0 {
		if _, ok := loadRepoFile(s.dir, id); !ok {
			return nil, fmt.Errorf("no scan history for repository %s: %w", id, ErrNotFound)
		}
		return &stateFile{Schema: fileSchema, RepoID: id, Findings: map[string]FindingState{}}, nil
	}
	_, sf := s.rebuildLocked(id, runs)
	return sf, nil
}

// Runs lists a repository's runs, newest first.
func (s *JSONStore) Runs(ctx context.Context, id RepoID, q RunQuery) ([]Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("reading scan history: %w", err)
	}
	if err := validateRepoID(id); err != nil {
		return nil, err
	}
	rf, err := s.repoFileFor(id)
	if err != nil {
		return nil, err
	}

	// Paging is anchored on a run rather than an offset so that a scan finishing
	// between two pages cannot shift the window and hide a run entirely.
	cutoff := len(rf.Runs)
	if q.Before != "" {
		cutoff = slices.IndexFunc(rf.Runs, func(r Run) bool { return r.ID == q.Before })
		if cutoff < 0 {
			return nil, fmt.Errorf("run %s is not in this repository's history: %w", q.Before, ErrNotFound)
		}
	}

	out := make([]Run, 0, min(cutoff, 64))
	for i := cutoff - 1; i >= 0; i-- {
		run := rf.Runs[i]
		if !q.matches(run) {
			continue
		}
		out = append(out, run)
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, nil
}

// matches reports whether a run passes the query's filters.
func (q RunQuery) matches(run Run) bool {
	if q.Branch != "" && run.VCS.Branch != q.Branch {
		return false
	}
	if !q.Since.IsZero() && run.FinishedAt.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && !run.FinishedAt.Before(q.Until) {
		return false
	}
	return true
}

// RunByID returns one run's metadata.
func (s *JSONStore) RunByID(ctx context.Context, id RepoID, run RunID) (Run, error) {
	if err := ctx.Err(); err != nil {
		return Run{}, fmt.Errorf("reading scan history: %w", err)
	}
	if err := validateRepoID(id); err != nil {
		return Run{}, err
	}
	if err := validateRunID(run); err != nil {
		return Run{}, err
	}
	rf, err := s.repoFileFor(id)
	if err != nil {
		return Run{}, err
	}
	for _, r := range rf.Runs {
		if r.ID == run {
			return r, nil
		}
	}
	return Run{}, fmt.Errorf("run %s is not in this repository's history: %w", run, ErrNotFound)
}

// Document returns a run's stored report.
//
// An unreadable run is an error here rather than a zero document, because the
// caller asked for the findings and there are none to give. The message carries
// the problem recorded on the run, which names the file so a user can decide
// what to do with it — this package never deletes it for them.
func (s *JSONStore) Document(ctx context.Context, id RepoID, run RunID) (report.Document, error) {
	if err := ctx.Err(); err != nil {
		return report.Document{}, fmt.Errorf("reading scan history: %w", err)
	}
	lr, err := s.loadedRun(id, run)
	if err != nil {
		return report.Document{}, err
	}
	if !lr.readable() {
		return report.Document{}, errors.New(lr.problem)
	}
	return lr.doc, nil
}

// loadedRun reads one run file after validating both identifiers.
func (s *JSONStore) loadedRun(id RepoID, run RunID) (loadedRun, error) {
	if err := validateRepoID(id); err != nil {
		return loadedRun{}, err
	}
	if err := validateRunID(run); err != nil {
		return loadedRun{}, err
	}
	path := runPath(s.dir, id, run)
	if _, err := os.Stat(path); err != nil {
		return loadedRun{}, fmt.Errorf("run %s is not in this repository's history: %w", run, ErrNotFound)
	}
	return loadRun(path, run), nil
}

// Findings returns a run's findings paired with the status each held then.
func (s *JSONStore) Findings(ctx context.Context, id RepoID, run RunID, q FindingQuery) ([]scan.Delta, error) {
	doc, err := s.Document(ctx, id, run)
	if err != nil {
		return nil, err
	}

	deltas := make([]scan.Delta, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		deltas = append(deltas, scan.Delta{Status: statusOf(doc, f), Finding: f})
	}
	return page(filterDeltas(deltas, q), q), nil
}

// statusOf returns the lifecycle status a document recorded for a finding.
//
// A finding with no recorded status reads as open rather than new: the only ways
// to get here are an unfingerprinted finding, which has no identity to have a
// history with, and a document written before statuses were recorded. Calling
// either one "new" would announce a wave of fresh problems on the first read of
// old history.
func statusOf(doc report.Document, f scan.Finding) scan.Status {
	if f.Fingerprint == "" {
		return scan.StatusNew
	}
	if st, ok := doc.Status[f.Fingerprint]; ok && st.Valid() {
		return st
	}
	return scan.StatusOpen
}

// States returns the lifecycle index, ordered most urgent first.
func (s *JSONStore) States(ctx context.Context, id RepoID, q FindingQuery) ([]FindingState, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("reading scan history: %w", err)
	}
	if err := validateRepoID(id); err != nil {
		return nil, err
	}
	sf, err := s.stateFor(id)
	if err != nil {
		return nil, err
	}

	states := make([]FindingState, 0, len(sf.Findings))
	for _, st := range sf.Findings {
		if !q.matchesState(st) {
			continue
		}
		states = append(states, st)
	}
	// Map iteration is random, so the order has to be imposed here: identical
	// history must render identically in a table and over the API.
	slices.SortFunc(states, func(a, b FindingState) int {
		if c := b.Severity.Rank() - a.Severity.Rank(); c != 0 {
			return c
		}
		if c := b.LastSeenAt.Compare(a.LastSeenAt); c != 0 {
			return c
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
	return page(states, q), nil
}

// matchesState reports whether a lifecycle entry passes the query's filters.
func (q FindingQuery) matchesState(st FindingState) bool {
	if len(q.Severity) > 0 && !slices.Contains(q.Severity, st.Severity) {
		return false
	}
	if len(q.Category) > 0 && !slices.Contains(q.Category, st.Category) {
		return false
	}
	if len(q.Status) > 0 && !slices.Contains(q.Status, st.Status) {
		return false
	}
	return true
}

// filterDeltas applies a query's filters to findings paired with statuses.
func filterDeltas(deltas []scan.Delta, q FindingQuery) []scan.Delta {
	if len(q.Severity) == 0 && len(q.Category) == 0 && len(q.Status) == 0 {
		return deltas
	}
	out := deltas[:0:0]
	for _, d := range deltas {
		if len(q.Severity) > 0 && !slices.Contains(q.Severity, d.Finding.Severity) {
			continue
		}
		if len(q.Category) > 0 && !slices.Contains(q.Category, d.Finding.Category) {
			continue
		}
		if len(q.Status) > 0 && !slices.Contains(q.Status, d.Status) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// page applies Offset and Limit. An offset past the end yields an empty slice
// rather than an error, because a page beyond the last one is a legitimate
// question with a legitimate empty answer.
func page[T any](items []T, q FindingQuery) []T {
	if q.Offset > 0 {
		if q.Offset >= len(items) {
			return nil
		}
		items = items[q.Offset:]
	}
	if q.Limit > 0 && q.Limit < len(items) {
		items = items[:q.Limit]
	}
	return items
}

// DiffRuns compares two runs.
//
// New, StillOpen and Fixed come from [scan.Diff], which matches on fingerprint
// alone. Two things are then layered on top, both of which need history that a
// pair of finding sets does not contain:
//
//   - A finding [scan.Diff] calls new, but whose status in the head run is
//     regressed, is reported as regressed. That is the distinction [scan.Diff]
//     documents it cannot make, and the run's own recorded statuses are what
//     make it cheap here.
//   - A finding present in base and absent from head is reported fixed only if
//     head could have observed it: a scanner that reported it ran, and the
//     exclusion set did not change between the two runs. Rules 1 and 2, applied
//     to an arbitrary pair rather than to consecutive runs. One that could not
//     be observed appears in no list at all, because the honest answer about it
//     is that nobody looked.
func (s *JSONStore) DiffRuns(ctx context.Context, id RepoID, req DiffRequest) (Diff, error) {
	if err := ctx.Err(); err != nil {
		return Diff{}, fmt.Errorf("reading scan history: %w", err)
	}
	if err := validateRepoID(id); err != nil {
		return Diff{}, err
	}
	rf, err := s.repoFileFor(id)
	if err != nil {
		return Diff{}, err
	}

	head, base, err := resolveDiffRuns(rf, req)
	if err != nil {
		return Diff{}, err
	}

	headDoc, err := s.Document(ctx, id, head.ID)
	if err != nil {
		return Diff{}, err
	}
	diff := Diff{Head: head.ID}

	var baseFindings []scan.Finding
	if base != nil {
		baseDoc, err := s.Document(ctx, id, base.ID)
		if err != nil {
			return Diff{}, err
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
		if sameExcludes && checkedBy(reportersOf(f), ran) {
			diff.Fixed = append(diff.Fixed, f)
		}
	}

	diff.Counts = DeltaCounts{
		New:       len(diff.New),
		StillOpen: len(diff.StillOpen),
		Fixed:     len(diff.Fixed),
		Regressed: len(diff.Regressed),
	}
	return diff, nil
}

// resolveDiffRuns turns a request into the two runs to compare. A nil base means
// there is nothing before head, in which case everything in head is new.
func resolveDiffRuns(rf *repoFile, req DiffRequest) (head *Run, base *Run, err error) {
	find := func(id RunID) (*Run, int, error) {
		i := slices.IndexFunc(rf.Runs, func(r Run) bool { return r.ID == id })
		if i < 0 {
			return nil, 0, fmt.Errorf("run %s is not in this repository's history: %w", id, ErrNotFound)
		}
		return &rf.Runs[i], i, nil
	}

	headIndex := len(rf.Runs) - 1
	if req.Head != "" {
		if err := validateRunID(req.Head); err != nil {
			return nil, nil, err
		}
		if head, headIndex, err = find(req.Head); err != nil {
			return nil, nil, err
		}
	} else {
		if headIndex < 0 {
			return nil, nil, fmt.Errorf("this repository has no runs to compare: %w", ErrNotFound)
		}
		head = &rf.Runs[headIndex]
	}

	if req.Base == "" {
		// The run immediately before head, which is the "what changed in this
		// scan" question. Not head.PrevRun, because a prune can have removed it.
		if headIndex > 0 {
			base = &rf.Runs[headIndex-1]
		}
		return head, base, nil
	}
	if err := validateRunID(req.Base); err != nil {
		return nil, nil, err
	}
	base, _, err = find(req.Base)
	if err != nil {
		return nil, nil, err
	}
	return head, base, nil
}

// reportersOf returns every scanner that reported a finding, from the merged
// list when [scan.Dedup] populated one and from the single field otherwise.
func reportersOf(f scan.Finding) []string {
	if len(f.Scanners) > 0 {
		return f.Scanners
	}
	if f.Scanner == "" {
		return nil
	}
	return []string{f.Scanner}
}

// The JSON store satisfies the interface it is written against, checked at
// compile time rather than at the first call site.
var _ Store = (*JSONStore)(nil)
