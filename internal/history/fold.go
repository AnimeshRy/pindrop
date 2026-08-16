package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// Fold holds in-memory repository state while recording or rebuilding scans.
type Fold struct {
	Repo    Repo
	Runs    []Run
	States  map[string]FindingState
	LastRun RunID
}

// runMeta is metadata a [report.Document] has nowhere to put.
type runMeta struct {
	RepoID     RepoID    `json:"repoId,omitempty"`
	StartedAt  time.Time `json:"startedAt,omitzero"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	ScopeHash  string    `json:"scopeHash,omitempty"`
}

// loadedRun is one run read from storage, readable or not.
type loadedRun struct {
	id      RunID
	doc     report.Document
	meta    runMeta
	problem string
}

func (r loadedRun) readable() bool { return r.problem == "" }

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

func decodeLoadedRun(id RunID, documentJSON string, meta runMeta) loadedRun {
	run := loadedRun{id: id, meta: meta}
	doc, err := report.DecodeDocument(bytes.NewReader([]byte(documentJSON)))
	if err != nil {
		run.problem = fmt.Sprintf("this run's record could not be decoded: %v", err)
		return run
	}
	run.doc = doc
	return run
}

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

func applyRun(f *Fold, lr loadedRun) (Run, map[string]scan.Status) {
	run := lr.run(f.Repo.ID)
	if n := len(f.Runs); n > 0 {
		run.PrevRun = f.Runs[n-1].ID
	}

	f.LastRun = lr.id

	var statuses map[string]scan.Status
	if lr.readable() {
		if f.States == nil {
			f.States = map[string]FindingState{}
		}
		at := run.FinishedAt
		if at.IsZero() {
			at = run.StartedAt
		}
		next, s, delta := advance(
			f.States,
			lr.doc.Findings,
			scannersThatRan(lr.doc.Scans),
			scopeChanged(f, run.ScopeHash),
			lr.id,
			at,
		)
		f.States = next
		statuses = s
		run.Delta = delta
	}

	f.Runs = append(f.Runs, run)
	f.Repo.Runs = len(f.Runs)
	f.Repo.LastRun = run.ID
	f.Repo.LastRunAt = run.FinishedAt
	if f.Repo.FirstRunAt.IsZero() {
		f.Repo.FirstRunAt = run.FinishedAt
	}
	f.Repo.Open = countOpen(f.States)

	return run, statuses
}

func scopeChanged(f *Fold, hash string) bool {
	if len(f.Runs) == 0 {
		return false
	}
	// Compare against the immediately previous run. Unreadable runs still carry
	// the scope hash that was recorded at Put time; skipping them lets a later
	// scan conclude findings fixed when an unreadable gap hid a scope change.
	return f.Runs[len(f.Runs)-1].ScopeHash != hash
}

func identify(f *Fold, root, origin string) {
	if f.Repo.Path != "" && f.Repo.Path != root {
		f.Repo.FormerPaths = append(f.Repo.FormerPaths, f.Repo.Path)
	}
	f.Repo.Path = root
	f.Repo.Name = repoName(root)
	if origin != "" {
		f.Repo.Origin = origin
	}
}

func documentFor(doc report.Document, repo Repo, at RunVCS, run RunID, finished time.Time) report.Document {
	doc.SchemaVersion = report.DocumentSchemaVersion
	if doc.GeneratedAt.IsZero() {
		doc.GeneratedAt = finished.UTC()
	}
	doc.RunID = string(run)
	if doc.Findings == nil {
		doc.Findings = []scan.Finding{}
	}

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

func encodeDocumentJSON(doc report.Document) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return "", fmt.Errorf("encoding scan document: %w", err)
	}
	return buf.String(), nil
}

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
			if at, ok := run.Time(); ok && now.Sub(at) > p.MaxAge {
				doomed = append(doomed, run)
			}
		}
	}
	return doomed
}

func statusOf(doc report.Document, f scan.Finding) scan.Status {
	if f.Fingerprint == "" {
		return scan.StatusNew
	}
	if st, ok := doc.Status[f.Fingerprint]; ok && st.Valid() {
		return st
	}
	return scan.StatusOpen
}

func resolveDiffRuns(runs []Run, req DiffRequest) (head *Run, base *Run, err error) {
	find := func(id RunID) (*Run, int, error) {
		i := indexRun(runs, id)
		if i < 0 {
			return nil, 0, fmt.Errorf("run %s is not in this repository's history: %w", id, ErrNotFound)
		}
		return &runs[i], i, nil
	}

	headIndex := len(runs) - 1
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
		head = &runs[headIndex]
	}

	if req.Base == "" {
		if headIndex > 0 {
			base = &runs[headIndex-1]
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

func indexRun(runs []Run, id RunID) int {
	for i, r := range runs {
		if r.ID == id {
			return i
		}
	}
	return -1
}

// Matches reports whether a run passes the query's filters.
func (q RunQuery) Matches(run Run) bool {
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

// MatchesState reports whether a lifecycle entry passes the query's filters.
func (q FindingQuery) MatchesState(st FindingState) bool {
	if len(q.Severity) > 0 && !containsSeverity(q.Severity, st.Severity) {
		return false
	}
	if len(q.Category) > 0 && !containsCategory(q.Category, st.Category) {
		return false
	}
	if len(q.Status) > 0 && !containsStatus(q.Status, st.Status) {
		return false
	}
	return true
}

func containsSeverity(list []scan.Severity, s scan.Severity) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func reportersOf(f scan.Finding) []string {
	if len(f.Scanners) > 0 {
		return f.Scanners
	}
	if f.Scanner == "" {
		return nil
	}
	return []string{f.Scanner}
}

func containsCategory(list []scan.Category, c scan.Category) bool {
	for _, v := range list {
		if v == c {
			return true
		}
	}
	return false
}

func containsStatus(list []scan.Status, s scan.Status) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func filterDeltas(deltas []scan.Delta, q FindingQuery) []scan.Delta {
	if len(q.Severity) == 0 && len(q.Category) == 0 && len(q.Status) == 0 {
		return deltas
	}
	out := deltas[:0:0]
	for _, d := range deltas {
		if len(q.Severity) > 0 && !containsSeverity(q.Severity, d.Finding.Severity) {
			continue
		}
		if len(q.Category) > 0 && !containsCategory(q.Category, d.Finding.Category) {
			continue
		}
		if len(q.Status) > 0 && !containsStatus(q.Status, d.Status) {
			continue
		}
		out = append(out, d)
	}
	return out
}

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

// RunRecord is one run's stored payload for rebuild and Put flows.
type RunRecord struct {
	ID           RunID
	DocumentJSON string
	StartedAt    time.Time
	FinishedAt   time.Time
	ScopeHash    string
}

// ApplyRunRecord folds one stored run into f and returns the run summary,
// per-fingerprint statuses, and the decoded document when readable.
func ApplyRunRecord(f *Fold, rec RunRecord) (Run, map[string]scan.Status, report.Document) {
	lr := loadedRun{
		id: rec.ID,
		meta: runMeta{
			RepoID:     f.Repo.ID,
			StartedAt:  rec.StartedAt,
			FinishedAt: rec.FinishedAt,
			ScopeHash:  rec.ScopeHash,
		},
	}
	if rec.DocumentJSON != "" {
		lr = decodeLoadedRun(rec.ID, rec.DocumentJSON, lr.meta)
	} else {
		lr.problem = "this run has no stored document"
	}
	run, statuses := applyRun(f, lr)
	return run, statuses, lr.doc
}

// EncodeDocumentJSON marshals a report document for storage.
func EncodeDocumentJSON(doc report.Document) (string, error) {
	return encodeDocumentJSON(doc)
}

// DocumentFor prepares a document for persistence.
func DocumentFor(doc report.Document, repo Repo, at RunVCS, run RunID, finished time.Time) report.Document {
	return documentFor(doc, repo, at, run, finished)
}

// Identify records where a run found the repository.
func Identify(f *Fold, root, origin string) {
	identify(f, root, origin)
}

// Expired returns run IDs that retention policy would delete.
func Expired(runs []RunID, p Retention, now time.Time) []RunID {
	return expired(runs, p, now)
}

// ResolveDiffRuns resolves a diff request against a run list.
func ResolveDiffRuns(runs []Run, req DiffRequest) (head *Run, base *Run, err error) {
	return resolveDiffRuns(runs, req)
}

// StatusOf returns the lifecycle status recorded for a finding in a document.
func StatusOf(doc report.Document, f scan.Finding) scan.Status {
	return statusOf(doc, f)
}

// FilterDeltas applies finding query filters to deltas.
func FilterDeltas(deltas []scan.Delta, q FindingQuery) []scan.Delta {
	return filterDeltas(deltas, q)
}

// Page applies offset and limit to a slice.
func Page[T any](items []T, q FindingQuery) []T {
	return page(items, q)
}

// ReportersOf returns scanners that reported a finding.
func ReportersOf(f scan.Finding) []string {
	return reportersOf(f)
}

// CanonicalRoot resolves a scanned path to the identity-bearing directory.
func CanonicalRoot(path string) (string, error) {
	return canonicalRoot(path)
}

// RepoIDFor derives a repository ID from a canonical path.
func RepoIDFor(canonical string) RepoID {
	return repoIDFor(canonical)
}

// MintRunIDAfter mints a run ID after the repository's newest run.
func MintRunIDAfter(finished time.Time, newest RunID) (RunID, error) {
	return mintRunIDAfter(finished, newest)
}

// ValidateRepoID checks repository ID shape.
func ValidateRepoID(id RepoID) error {
	return validateRepoID(id)
}

// ValidateRunID checks run ID shape.
func ValidateRunID(id RunID) error {
	return validateRunID(id)
}

// DBFileMode is the permission applied to the SQLite database file.
const DBFileMode = dbFileMode
