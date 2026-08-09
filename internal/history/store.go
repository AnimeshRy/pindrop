package history

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
	"github.com/AnimeshRy/pindrop/internal/vcs"
)

// JSONStore is a [Store] backed by a directory of JSON files. See the package
// doc for the layout.
type JSONStore struct {
	dir string

	// mu guards locks, which holds one mutex per repository. The file lock in
	// lock.go serializes separate processes; this serializes goroutines within
	// one, where O_EXCL against ourselves would simply spin until it timed out.
	mu    sync.Mutex
	locks map[RepoID]*sync.Mutex
}

// OpenJSON opens the store rooted at dir, creating it if needed.
//
// It takes a directory rather than calling [DefaultDir] itself so that tests,
// and a future --history-dir flag, do not have to move a user's home.
func OpenJSON(dir string) (*JSONStore, error) {
	if dir == "" {
		return nil, errors.New("opening scan history: no directory given")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving the scan history directory %q: %w", dir, err)
	}
	if err := os.MkdirAll(abs, dirMode); err != nil {
		return nil, fmt.Errorf("creating the scan history directory %s: %w", toolpath.Display(abs), err)
	}
	return &JSONStore{dir: abs, locks: map[RepoID]*sync.Mutex{}}, nil
}

// Close releases resources. The JSON store holds no handles between calls, so
// it has nothing to release; the method exists for the interface and for the
// backend that will.
func (s *JSONStore) Close() error { return nil }

// Dir returns the directory the store lives in, for error messages.
func (s *JSONStore) Dir() string { return s.dir }

// mutexFor returns the process-local mutex for a repository.
func (s *JSONStore) mutexFor(id RepoID) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.locks[id]
	if !ok {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	return m
}

// hold takes both locks for a repository and returns the release function.
func (s *JSONStore) hold(ctx context.Context, id RepoID) (func(), error) {
	m := s.mutexFor(id)
	m.Lock()
	lock, err := acquireLock(ctx, repoDir(s.dir, id))
	if err != nil {
		m.Unlock()
		return nil, err
	}
	return func() {
		lock.release()
		m.Unlock()
	}, nil
}

// Put records one completed scan.
//
// The ordering is chosen for what a crash leaves behind. The immutable run file
// is written first and the two derived files after, so an interruption loses at
// most the index — which the next Put rebuilds from the run files it finds — and
// never loses a scan result. The lifecycle fold happens before the write only so
// that the run file can carry its own statuses; it touches nothing durable.
func (s *JSONStore) Put(ctx context.Context, rec Record) (Run, error) {
	if err := ctx.Err(); err != nil {
		return Run{}, fmt.Errorf("recording scan history: %w", err)
	}
	if rec.Root == "" {
		return Run{}, errors.New("recording scan history: no scanned directory given")
	}

	root, err := canonicalRoot(rec.Root)
	if err != nil {
		return Run{}, err
	}
	id := repoIDFor(root)
	if existing, ok := s.detectMove(id, root, rec.VCS.Origin); ok {
		id = existing
	}

	release, err := s.hold(ctx, id)
	if err != nil {
		return Run{}, err
	}
	defer release()

	rf, sf, err := s.loadForWrite(id, root, rec)
	if err != nil {
		return Run{}, err
	}

	finished := rec.FinishedAt
	if finished.IsZero() {
		finished = time.Now().UTC()
	}
	newest := RunID("")
	if n := len(rf.Runs); n > 0 {
		newest = rf.Runs[n-1].ID
	}
	runID, err := mintRunIDAfter(finished, newest)
	if err != nil {
		return Run{}, err
	}

	lr := loadedRun{
		id:  runID,
		doc: documentFor(rec.Document, rf.Repo, rec.VCS, runID, finished),
		meta: runMeta{
			RepoID:     id,
			StartedAt:  rec.StartedAt.UTC(),
			FinishedAt: finished.UTC(),
			ScopeHash:  rec.ScopeHash,
		},
	}
	run, statuses := applyRun(rf, sf, lr)
	if len(statuses) > 0 {
		lr.doc.Status = statuses
	}

	if err := writeJSONAtomic(runPath(s.dir, id, runID), runFile{Document: lr.doc, History: lr.meta}); err != nil {
		return Run{}, err
	}
	if err := save(s.dir, rf, sf); err != nil {
		return Run{}, err
	}
	return run, nil
}

// loadForWrite returns the derived files to fold the new run into, repairing
// them first when they are missing, corrupt, or behind the run files on disk.
//
// The third case is the crash-gap: a previous Put wrote its run file and died
// before its index. Replaying from the run files here is what makes that
// recoverable without the user knowing it happened.
func (s *JSONStore) loadForWrite(id RepoID, root string, rec Record) (*repoFile, *stateFile, error) {
	runs, err := listRuns(s.dir, id)
	if err != nil {
		return nil, nil, err
	}

	rf, rfOK := loadRepoFile(s.dir, id)
	sf, sfOK := loadStateFile(s.dir, id)

	newest := RunID("")
	if len(runs) > 0 {
		newest = runs[len(runs)-1]
	}
	if !rfOK || !sfOK || sf.LastRun != newest || len(rf.Runs) != len(runs) {
		if rfOK || sfOK || len(runs) > 0 {
			slog.Debug("rebuilding scan history index",
				"repo", id, "runs", len(runs), "hadRepoFile", rfOK, "hadStateFile", sfOK)
		}
		rf, sf = s.rebuildLocked(id, runs)
	}

	identify(rf, id, root, rec.VCS.Origin)
	return rf, sf, nil
}

// identify records where this run found the repository, moving the previously
// recorded path onto FormerPaths when it changed.
func identify(rf *repoFile, id RepoID, root, origin string) {
	rf.Repo.ID = id
	if rf.Repo.Path != "" && rf.Repo.Path != root {
		rf.Repo.FormerPaths = append(rf.Repo.FormerPaths, rf.Repo.Path)
	}
	rf.Repo.Path = root
	rf.Repo.Name = filepath.Base(root)
	// An origin that disappeared — a remote removed, or a scan of an export —
	// does not erase the one we knew, because it is what move detection matches
	// on and losing it strands the repository at its old path.
	if origin != "" {
		rf.Repo.Origin = origin
	}
}

// documentFor returns the document to persist: the caller's, with the fields
// only the store can fill.
//
// The schema version is set to this build's rather than preserved. A stored run
// is written by this binary, whatever version produced the findings, and an old
// version number on a file carrying v2 fields would be a lie that
// [report.DecodeDocument] believes.
func documentFor(doc report.Document, repo Repo, at RunVCS, run RunID, finished time.Time) report.Document {
	doc.SchemaVersion = report.DocumentSchemaVersion
	if doc.GeneratedAt.IsZero() {
		doc.GeneratedAt = finished.UTC()
	}
	doc.RunID = string(run)
	if doc.Findings == nil {
		doc.Findings = []scan.Finding{}
	}

	// The record's VCS wins, since it was read at scan time; anything the caller
	// had already put on the document is a fallback rather than a conflict.
	branch, commit := at.Branch, at.Commit
	if doc.Repo != nil {
		if branch == "" {
			branch = doc.Repo.Branch
		}
		if commit == "" {
			commit = doc.Repo.Commit
		}
	}
	doc.Repo = &report.Repo{
		ID:     string(repo.ID),
		Name:   repo.Name,
		Path:   repo.Path,
		Origin: repo.Origin,
		Branch: branch,
		Commit: commit,
	}
	return doc
}

// Rebuild regenerates repo.json and state.json from the run files.
func (s *JSONStore) Rebuild(ctx context.Context, id RepoID) error {
	if err := validateRepoID(id); err != nil {
		return err
	}
	release, err := s.hold(ctx, id)
	if err != nil {
		return err
	}
	defer release()

	runs, err := listRuns(s.dir, id)
	if err != nil {
		return err
	}
	rf, sf := s.rebuildLocked(id, runs)
	return save(s.dir, rf, sf)
}

// rebuildLocked replays every run file in commit order. The caller must hold the
// repository's lock.
//
// Unreadable runs are replayed too, in the sense that they take their place in
// the run list and advance the index's cursor — but their findings are not
// folded in, so nothing they would have reported is concluded fixed. Their
// absence is unknown, not resolved.
func (s *JSONStore) rebuildLocked(id RepoID, runs []RunID) (*repoFile, *stateFile) {
	rf := &repoFile{Schema: fileSchema, Repo: Repo{ID: id}}
	reconstruct := true
	if existing, ok := loadRepoFile(s.dir, id); ok {
		// The identity fields are the only thing repo.json knows that the run
		// files do not: FormerPaths exists nowhere else.
		rf.Repo = existing.Repo
		rf.Repo.ID = id
		rf.Repo.Runs, rf.Repo.LastRun, rf.Repo.LastRunAt = 0, "", time.Time{}
		rf.Repo.FirstRunAt = time.Time{}
		rf.Repo.Open = Counts{}
		reconstruct = false
	}
	sf := &stateFile{Schema: fileSchema, RepoID: id, Findings: map[string]FindingState{}}

	for _, run := range runs {
		lr := loadRun(runPath(s.dir, id, run), run)
		applyRun(rf, sf, lr)
		if reconstruct && lr.readable() && lr.doc.Repo != nil {
			// Newest wins: the loop runs oldest to newest.
			rf.Repo.Path = lr.doc.Repo.Path
			rf.Repo.Name = lr.doc.Repo.Name
			rf.Repo.Origin = lr.doc.Repo.Origin
		}
	}
	return rf, sf
}

// Prune deletes old runs, keeping the newest one whatever p says.
//
// Deleting a run deletes the history it carried, so the index is rebuilt from
// what remains: a finding whose only sighting was in a pruned run disappears
// rather than lingering as an open issue nobody can trace. That is the honest
// consequence of retention, and it is why the newest run is never a candidate —
// a repository whose entire index came from one run must keep that run.
func (s *JSONStore) Prune(ctx context.Context, id RepoID, p Retention) (int, error) {
	if err := validateRepoID(id); err != nil {
		return 0, err
	}
	release, err := s.hold(ctx, id)
	if err != nil {
		return 0, err
	}
	defer release()

	runs, err := listRuns(s.dir, id)
	if err != nil {
		return 0, err
	}
	doomed := expired(runs, p, time.Now().UTC())
	if len(doomed) == 0 {
		return 0, nil
	}

	deleted := 0
	for _, run := range doomed {
		path := runPath(s.dir, id, run)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return deleted, fmt.Errorf("deleting %s: %w", toolpath.Display(path), err)
		}
		deleted++
	}

	remaining, err := listRuns(s.dir, id)
	if err != nil {
		return deleted, err
	}
	rf, sf := s.rebuildLocked(id, remaining)
	if err := save(s.dir, rf, sf); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// expired returns the runs p discards, given the full list in commit order.
// The newest is never returned, so a Prune can never leave a repository with no
// runs at all.
func expired(runs []RunID, p Retention, now time.Time) []RunID {
	if p.keepsEverything() || len(runs) < 2 {
		return nil
	}
	candidates := runs[:len(runs)-1]

	var doomed []RunID
	for i, run := range candidates {
		switch {
		case p.MaxRuns > 0 && len(runs)-i > p.MaxRuns:
			doomed = append(doomed, run)
		case p.MaxAge > 0:
			// The timestamp comes from the ID, so age-based pruning opens no
			// files — including the unreadable ones, which age out like any
			// other rather than accumulating forever.
			if at, ok := run.Time(); ok && now.Sub(at) > p.MaxAge {
				doomed = append(doomed, run)
			}
		}
	}
	return doomed
}

// Forget deletes a repository's history entirely.
func (s *JSONStore) Forget(ctx context.Context, id RepoID) error {
	if err := validateRepoID(id); err != nil {
		return err
	}
	release, err := s.hold(ctx, id)
	if err != nil {
		return err
	}
	// The lock file lives inside the directory being removed, so it is released
	// before the removal rather than after it.
	release()

	dir := repoDir(s.dir, id)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("deleting %s: %w", toolpath.Display(dir), err)
	}
	return nil
}

// detectMove finds the repository a moved checkout used to be, when there is
// exactly one unambiguous answer.
//
// Both conditions are required: an identical origin, and a recorded path that no
// longer exists. Origin alone would merge two live checkouts of one repository —
// a worktree, a fork, a release branch beside main — into a single history, and
// every branch switch would then report a wave of fixed-and-regressed findings.
// A vanished path alone would adopt the history of an unrelated deleted project.
// Two candidates means the answer is a guess, and a guess here silently
// rewrites a user's history, so it declines instead.
func (s *JSONStore) detectMove(id RepoID, root, origin string) (RepoID, bool) {
	if origin == "" {
		return "", false
	}
	if _, ok := loadRepoFile(s.dir, id); ok {
		return "", false // already known at this path; nothing moved
	}

	var found RepoID
	for _, other := range s.repoIDs() {
		if other == id {
			continue
		}
		rf, ok := loadRepoFile(s.dir, other)
		if !ok || rf.Repo.Origin != origin || rf.Repo.Path == "" || rf.Repo.Path == root {
			continue
		}
		if _, err := os.Stat(rf.Repo.Path); err == nil {
			continue // that checkout is still there, so this is a second one
		}
		if found != "" {
			return "", false
		}
		found = other
	}
	if found == "" {
		return "", false
	}
	slog.Debug("adopting scan history from a repository that moved", "repo", found, "to", root)
	return found, true
}

// repoIDs lists the repository directories in the store.
//
// A directory whose name is not a valid [RepoID] is ignored rather than
// reported: the store's directory is a user's home, and a stray file there is
// not an error worth interrupting a scan for.
func (s *JSONStore) repoIDs() []RepoID {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		slog.Debug("reading scan history", "dir", s.dir, "err", err)
		return nil
	}
	ids := make([]RepoID, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := RepoID(e.Name())
		if !id.Valid() {
			slog.Debug("ignoring unrecognized entry in scan history", "name", e.Name())
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// canonicalRoot reduces a scanned path to the identity-bearing directory.
//
// It roots at the git work tree when there is one, so that `pindrop scan .` and
// `pindrop scan ./internal` record against the same repository rather than two.
// Symlinks are resolved because /tmp and /var/tmp are the same directory on
// macOS and a user should not get two histories for choosing a different spelling
// — but a path that does not exist keeps its literal form, since [Store.RepoByPath]
// is asked about deleted checkouts on purpose.
//
// The case is left alone. Lowercasing would merge two genuinely distinct
// directories on Linux, which is the platform where getting it wrong corrupts
// data rather than merely surprising someone.
func canonicalRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q to an absolute path: %w", path, err)
	}

	base := abs
	if info, err := vcs.Inspect(abs); err == nil && info.Root != "" {
		base = info.Root
	}
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	if base, err = filepath.Abs(base); err != nil {
		return "", fmt.Errorf("resolving %q to an absolute path: %w", path, err)
	}
	return filepath.Clean(base), nil
}

// repoIDFor derives the stable identity of a repository from its canonical path.
//
// The "path:" prefix is a domain separator: the day a second kind of identity
// exists — a container image, a cloud account, anything with no path at all —
// its digests must not be able to collide with these.
func repoIDFor(canonical string) RepoID {
	sum := sha256.Sum256([]byte("path:" + canonical))
	return RepoID("r_" + hex.EncodeToString(sum[:16]))
}

// mintRunID creates a run's identity at commit time.
//
// The timestamp comes from when the scan finished, so lexicographic order is
// commit order and pruning by age needs no file reads. The random suffix is what
// makes two scans that finish in the same second land in different files instead
// of one overwriting the other; it is randomness rather than a counter because a
// counter would have to be read from somewhere, and the somewhere would be a
// file two processes are racing on.
func mintRunID(finished time.Time) (RunID, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generating a run identifier: %w", err)
	}
	return RunID(finished.UTC().Format(runIDLayout) + "-" + hex.EncodeToString(suffix[:])), nil
}

// mintRunIDAfter mints an ID that sorts after the repository's newest run.
//
// Two scans of one repository can finish within the same second, and a clock can
// go backwards across a daylight-saving change or an ntp correction. Either
// would make lexicographic order stop being commit order, which is the property
// a rebuild relies on to replay history in the order it happened. Nudging the
// encoded second forward costs at most two attempts and keeps the invariant; the
// run's real timing is recorded separately and is not touched.
func mintRunIDAfter(finished time.Time, newest RunID) (RunID, error) {
	for range 4 {
		id, err := mintRunID(finished)
		if err != nil {
			return "", err
		}
		if newest == "" || id > newest {
			return id, nil
		}
		if at, ok := newest.Time(); ok && !finished.After(at) {
			finished = at.Add(time.Second)
			continue
		}
		finished = finished.Add(time.Second)
	}
	return "", errors.New("generating a run identifier: the clock is too far behind this repository's newest run")
}

// validateRepoID rejects an ID that is not exactly the shape this package mints.
//
// These values arrive from HTTP path segments, and the next thing that happens
// to one is filepath.Join. Rejection is deliberate rather than sanitization:
// cleaning "../.." into something safe produces a different valid-looking ID
// that addresses the wrong repository, which trades a traversal for a silent
// mix-up. The message names the value because a user pasting a URL needs to see
// what was wrong with it.
func validateRepoID(id RepoID) error {
	if !id.Valid() {
		return fmt.Errorf("%q is not a repository id (expected r_ followed by 32 hex characters): %w", string(id), ErrNotFound)
	}
	return nil
}

// validateRunID rejects an ID that is not exactly the shape this package mints;
// see [validateRepoID].
func validateRunID(id RunID) error {
	if !id.Valid() {
		return fmt.Errorf("%q is not a run id (expected 20060102T150405Z-abcdef12): %w", string(id), ErrNotFound)
	}
	return nil
}
