package history

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// On-disk names. runs/ is a subdirectory rather than a prefix so that listing
// runs is a ReadDir that cannot see repo.json, state.json or the lock.
const (
	repoFileName  = "repo.json"
	stateFileName = "state.json"
	runsDirName   = "runs"
	runFileSuffix = ".json"
)

// fileSchema versions the two derived files. They are caches of the run files,
// so an unrecognized version is not an error — it is a reason to rebuild.
const fileSchema = 1

// repoFile is the on-disk repo.json: a repository's identity plus the list of
// its runs, oldest first.
//
// The run list lives here rather than in a separate index because it is written
// under the same lock, in the same Put, as the repository summary it belongs to
// — two files would be two things that can disagree. It is derived from the run
// files and [Store.Rebuild] regenerates it.
type repoFile struct {
	Schema int   `json:"schema"`
	Repo   Repo  `json:"repo"`
	Runs   []Run `json:"runs"`
}

// stateFile is the on-disk state.json: the fingerprint lifecycle index.
//
// LastRun is the newest run this index has folded in, *including* one that could
// not be read. Recording an unreadable run here is what stops every subsequent
// Put from detecting the same permanent gap and replaying all of history again.
type stateFile struct {
	Schema   int                     `json:"schema"`
	RepoID   RepoID                  `json:"repoId"`
	LastRun  RunID                   `json:"lastRun,omitempty"`
	Findings map[string]FindingState `json:"findings"`
}

// runMeta is the run metadata a [report.Document] has nowhere to put: the wall
// clock boundaries of the scan, and the exclusion hash rule 2 compares.
//
// It rides in the run file under a "history" key, alongside the document's own
// fields rather than wrapping them, so that the file is still exactly a
// [report.Document] — `pindrop serve --results <that file>` works on any run
// file, and [report.DecodeDocument] stays the only thing that reads a document.
// A consumer that does not know about this key ignores it, which is what JSON
// decoding does with unknown fields by default.
type runMeta struct {
	RepoID     RepoID    `json:"repoId,omitempty"`
	StartedAt  time.Time `json:"startedAt,omitzero"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	ScopeHash  string    `json:"scopeHash,omitempty"`
}

// runFile is what gets written: a document with the extra key inlined.
type runFile struct {
	report.Document
	History runMeta `json:"history"`
}

// loadedRun is one run file read from disk, readable or not.
type loadedRun struct {
	id   RunID
	doc  report.Document
	meta runMeta

	// problem is empty for a readable run and otherwise explains, in terms a
	// user can act on, why the file could not be used.
	problem string
}

// readable reports whether this run's findings can be trusted.
func (r loadedRun) readable() bool { return r.problem == "" }

// loadRun reads one run file.
//
// A file that cannot be decoded never becomes an error the caller has to handle
// by giving up: it becomes a run marked unreadable. Deleting or skipping a
// stored scan result because this build cannot parse it would be the worst
// possible behavior for a security product — the result may be the only record
// that a vulnerability was ever present — so the file stays exactly where it is
// and the problem is carried forward to the user.
func loadRun(path string, id RunID) loadedRun {
	run := loadedRun{id: id}

	// #nosec G304 -- the path is the store directory plus a validated RepoID,
	// "runs", and a validated RunID; none of it is caller-supplied text.
	raw, err := os.ReadFile(path)
	if err != nil {
		run.problem = fmt.Sprintf("this run's file could not be read (%v); it is still on disk at %s", err, path)
		return run
	}

	doc, err := report.DecodeDocument(bytes.NewReader(raw))
	if err != nil {
		run.problem = fmt.Sprintf("this run's file could not be decoded: %v", err)
		return run
	}
	run.doc = doc

	// The metadata block is optional: a run file that lost it is still a usable
	// document, just one whose timings have to be inferred.
	var extra struct {
		History runMeta `json:"history"`
	}
	if err := json.Unmarshal(raw, &extra); err == nil {
		run.meta = extra.History
	}
	return run
}

// run projects a loaded file into the [Run] a list view shows. Delta is left
// zero; only the lifecycle fold can fill it.
func (r loadedRun) run(repoID RepoID) Run {
	out := Run{
		ID:         r.id,
		RepoID:     repoID,
		StartedAt:  r.meta.StartedAt,
		FinishedAt: r.meta.FinishedAt,
		ScopeHash:  r.meta.ScopeHash,
	}
	if !r.readable() {
		out.Unreadable = true
		out.Problem = r.problem
		// The ID's timestamp is the only fact still legible about a broken run,
		// and a run with no time at all sorts and filters as if it were from
		// 1970.
		if at, ok := r.id.Time(); ok {
			out.StartedAt, out.FinishedAt = at, at
		}
		return out
	}

	out.Tool = r.doc.Tool
	out.Scanners = r.doc.Scans
	out.Counts = countFindings(r.doc.Findings)
	if r.doc.Repo != nil {
		out.VCS = RunVCS{
			Origin: r.doc.Repo.Origin,
			Branch: r.doc.Repo.Branch,
			Commit: r.doc.Repo.Commit,
		}
	}

	if out.FinishedAt.IsZero() {
		out.FinishedAt = r.doc.GeneratedAt
	}
	if out.StartedAt.IsZero() {
		out.StartedAt = earliestScanStart(r.doc.Scans, out.FinishedAt)
	}
	if !out.StartedAt.IsZero() && !out.FinishedAt.IsZero() {
		if d := out.FinishedAt.Sub(out.StartedAt); d > 0 {
			out.DurationMS = d.Milliseconds()
		}
	}
	return out
}

// earliestScanStart returns the first moment any scanner started, falling back
// to fallback when no summary carries a time.
func earliestScanStart(scans []report.ScanSummary, fallback time.Time) time.Time {
	earliest := time.Time{}
	for _, s := range scans {
		if s.StartedAt.IsZero() {
			continue
		}
		if earliest.IsZero() || s.StartedAt.Before(earliest) {
			earliest = s.StartedAt
		}
	}
	if earliest.IsZero() {
		return fallback
	}
	return earliest
}

// applyRun folds one run into the derived files, returning the run as recorded
// and the per-fingerprint statuses it concluded.
//
// It is the single path by which a run reaches the lifecycle index: a live Put
// calls it once, and a rebuild calls it once per run in commit order. Having one
// implementation is what guarantees a rebuilt index equals the incrementally
// maintained one, which is the property that lets state.json be thrown away.
func applyRun(rf *repoFile, sf *stateFile, lr loadedRun) (Run, map[string]scan.Status) {
	run := lr.run(rf.Repo.ID)
	if n := len(rf.Runs); n > 0 {
		run.PrevRun = rf.Runs[n-1].ID
	}

	// Recorded even when unreadable, so the gap check converges rather than
	// replaying every run forever.
	sf.LastRun = lr.id

	var statuses map[string]scan.Status
	if lr.readable() {
		if sf.Findings == nil {
			sf.Findings = map[string]FindingState{}
		}
		at := run.FinishedAt
		if at.IsZero() {
			at = run.StartedAt
		}
		next, s, delta := advance(
			sf.Findings,
			lr.doc.Findings,
			scannersThatRan(lr.doc.Scans),
			scopeChanged(rf, run.ScopeHash),
			lr.id,
			at,
		)
		sf.Findings = next
		statuses = s
		run.Delta = delta
	}

	rf.Runs = append(rf.Runs, run)
	rf.Repo.Runs = len(rf.Runs)
	rf.Repo.LastRun = run.ID
	rf.Repo.LastRunAt = run.FinishedAt
	if rf.Repo.FirstRunAt.IsZero() {
		rf.Repo.FirstRunAt = run.FinishedAt
	}
	rf.Repo.Open = countOpen(sf.Findings)

	return run, statuses
}

// scopeChanged reports whether hash differs from the most recent readable
// run's exclusion hash.
//
// The comparison is against the last run that could be read, not the last run:
// an unreadable file in between says nothing about exclusions, and treating it
// as a change would suspend fixed-detection for a run that is otherwise fine.
// With no previous readable run there is nothing in the index to mark fixed, so
// the answer does not matter and false keeps the first run's delta clean.
func scopeChanged(rf *repoFile, hash string) bool {
	for i := len(rf.Runs) - 1; i >= 0; i-- {
		if rf.Runs[i].Unreadable {
			continue
		}
		return rf.Runs[i].ScopeHash != hash
	}
	return false
}

// repoDir returns the directory holding one repository's history. The ID is
// validated by every caller before it gets here; this function assumes it.
func repoDir(root string, id RepoID) string { return filepath.Join(root, string(id)) }

// runPath returns the path of one run file.
func runPath(root string, id RepoID, run RunID) string {
	return filepath.Join(repoDir(root, id), runsDirName, string(run)+runFileSuffix)
}

// listRuns returns the run IDs on disk in commit order.
//
// Lexicographic order is commit order because a [RunID] starts with a UTC
// timestamp, which is why this needs no file reads at all. Anything in the
// directory that is not a valid run file name is ignored: a stray file is not a
// run, and guessing at one would put unattributable findings into a user's
// history.
func listRuns(root string, id RepoID) ([]RunID, error) {
	dir := filepath.Join(repoDir(root, id), runsDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	runs := make([]RunID, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name, ok := strings.CutSuffix(e.Name(), runFileSuffix)
		if !ok {
			continue
		}
		if run := RunID(name); run.Valid() {
			runs = append(runs, run)
		}
	}
	slices.Sort(runs)
	return runs, nil
}

// loadRepoFile reads repo.json, or reports that it is unusable.
func loadRepoFile(root string, id RepoID) (*repoFile, bool) {
	// #nosec G304 -- store directory plus a validated RepoID and a constant name.
	raw, err := os.ReadFile(filepath.Join(repoDir(root, id), repoFileName))
	if err != nil {
		return nil, false
	}
	var rf repoFile
	if err := json.Unmarshal(raw, &rf); err != nil || rf.Schema != fileSchema {
		return nil, false
	}
	return &rf, true
}

// loadStateFile reads state.json, or reports that it is unusable. A corrupt
// index is never an error a user sees: it is fully derived, so the answer is to
// rebuild it, in the spirit of toolinstall.LoadRecord.
func loadStateFile(root string, id RepoID) (*stateFile, bool) {
	// #nosec G304 -- store directory plus a validated RepoID and a constant name.
	raw, err := os.ReadFile(filepath.Join(repoDir(root, id), stateFileName))
	if err != nil {
		return nil, false
	}
	var sf stateFile
	if err := json.Unmarshal(raw, &sf); err != nil || sf.Schema != fileSchema {
		return nil, false
	}
	if sf.Findings == nil {
		sf.Findings = map[string]FindingState{}
	}
	return &sf, true
}

// save writes both derived files. repo.json goes last, so that a crash between
// them leaves a repository whose run list is behind its index rather than ahead
// of it — the direction the next Put's gap replay repairs.
func save(root string, rf *repoFile, sf *stateFile) error {
	rf.Schema = fileSchema
	sf.Schema = fileSchema
	dir := repoDir(root, rf.Repo.ID)

	if err := writeJSONAtomic(filepath.Join(dir, stateFileName), sf); err != nil {
		return err
	}
	return writeJSONAtomic(filepath.Join(dir, repoFileName), rf)
}
