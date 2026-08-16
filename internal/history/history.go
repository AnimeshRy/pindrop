// Package history persists every scan, so that the second run of Pindrop can
// answer the question the first one cannot: did the thing I fixed actually get
// fixed?
//
// A scanner reports what is wrong now. A user needs to know what changed, and
// specifically whether an issue they addressed is gone or merely unobserved.
// That distinction is the whole feature, and getting it wrong in the optimistic
// direction — reporting "fixed" for something nobody fixed — is worse than
// reporting nothing at all, because it is the one output a user will act on
// without checking.
//
// # The three rules
//
// Everything here exists to keep three invariants, all of them about not
// concluding "fixed" too eagerly:
//
//  1. A finding is fixed only if a scanner that previously reported it actually
//     ran. `pindrop scan --scanners vuln` must not mark every secret fixed
//     because TruffleHog never ran. [Run.Scanners] is load-bearing, not
//     descriptive.
//  2. A finding is not fixed when it vanished because the exclusion set changed.
//     [Record.ScopeHash] is compared against the previous run's, and a
//     difference suspends fixed-detection for that run.
//  3. Regression is read from the lifecycle index in constant time per finding,
//     never by replaying history. "Was this ever fixed before?" is a property of
//     a finding's whole life, which is exactly why [scan.Diff] cannot answer it.
//
// The fold that enforces all three is [advance], which is pure and has no I/O
// precisely so that it can be tested exhaustively without a filesystem.
//
// # Storage
//
// Scan history lives in a single SQLite database at ~/.pindrop/pindrop.db.
// [github.com/AnimeshRy/pindrop/internal/history/sqlite.Open] returns the
// only implementation today.
//
// The database holds four tables: repos, runs, findings, and finding_states.
// Run rows store the full [report.Document] blob; findings are also normalized
// into rows for query speed; finding_states is the fingerprint lifecycle index.
// Goose migrations in internal/history/sqlite/migrations version the schema.
//
// The [Store] interface is shaped for a Postgres backend to slot in later: every
// method is context-carrying, takes a repository scope, and returns whole values
// rather than cursors.
package history

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

// ErrNotFound reports that a repository or run does not exist.
//
// It is a package sentinel rather than [os.ErrNotExist] on purpose. Callers —
// the HTTP API above all — must be able to tell "no such run" from "the store's
// own file is missing", and a store backed by SQLite would never produce a
// filesystem error for the first case at all. Test for it with [errors.Is].
var ErrNotFound = errors.New("not found")

// A Store keeps scan history and answers questions about it.
//
// Every method takes a context because a later backend will do I/O that is worth
// cancelling; the JSON implementation checks it between files rather than
// pretending each read is interruptible.
//
// Implementations must be safe for concurrent use, including from separate
// processes: two `pindrop scan` runs against the same repository are a normal
// thing for a user to do.
type Store interface {
	// Put records one completed scan and returns the run it created. It is the
	// only method that writes findings, and the only one that advances the
	// lifecycle index.
	Put(ctx context.Context, rec Record) (Run, error)

	// Repos lists every repository with history, most recently scanned first.
	Repos(ctx context.Context) ([]Repo, error)

	// RepoByID returns one repository, or [ErrNotFound].
	RepoByID(ctx context.Context, id RepoID) (Repo, error)

	// RepoByPath returns the repository a directory belongs to, resolving it the
	// same way [Put] would — so a subdirectory of a work tree finds the
	// repository rooted at the work tree.
	RepoByPath(ctx context.Context, path string) (Repo, error)

	// Runs lists a repository's runs, newest first, filtered by q.
	Runs(ctx context.Context, id RepoID, q RunQuery) ([]Run, error)

	// RunByID returns one run's metadata, or [ErrNotFound].
	RunByID(ctx context.Context, id RepoID, run RunID) (Run, error)

	// Findings returns a run's findings paired with the lifecycle status each
	// held as of that run.
	Findings(ctx context.Context, id RepoID, run RunID, q FindingQuery) ([]scan.Delta, error)

	// Document returns the stored report for a run, exactly as it was written.
	Document(ctx context.Context, id RepoID, run RunID) (report.Document, error)

	// States returns the lifecycle index: one entry per fingerprint ever seen in
	// this repository, including findings that are currently fixed.
	States(ctx context.Context, id RepoID, q FindingQuery) ([]FindingState, error)

	// DiffRuns compares two runs of one repository.
	DiffRuns(ctx context.Context, id RepoID, req DiffRequest) (Diff, error)

	// Rebuild regenerates the derived files from the run files. It is called
	// automatically when they are missing or unreadable, and is exposed so a
	// user can be told to run it.
	Rebuild(ctx context.Context, id RepoID) error

	// Prune deletes old runs according to p and reports how many it removed. It
	// never deletes the newest run.
	Prune(ctx context.Context, id RepoID, p Retention) (deleted int, err error)

	// Forget deletes a repository's entire history.
	Forget(ctx context.Context, id RepoID) error

	// Close releases resources. It is safe to call more than once.
	Close() error
}

// DefaultDBPath returns the path to the scan history database, ~/.pindrop/pindrop.db.
// It creates nothing.
func DefaultDBPath() (string, error) { return toolpath.DBPath() }

// A RepoID identifies a repository across runs: "r_" followed by 32 hex
// characters.
//
// It is derived from the canonical path of the work-tree root, never from the
// git remote. Two live checkouts of one repository — a linked worktree, a fork,
// a release branch beside main — genuinely have different findings, and merging
// them by remote would report a wave of fixed-and-regressed on every branch
// switch. Origin is display metadata and a move-detection hint, nothing more.
type RepoID string

// repoIDPattern is the only shape a RepoID may take. It exists because these
// values arrive from HTTP path segments and are then joined to a directory.
var repoIDPattern = regexp.MustCompile(`^r_[0-9a-f]{32}$`)

// Valid reports whether id is well formed.
//
// Every entry point validates before an ID reaches a filesystem path, and
// rejects rather than sanitizes: cleaning a hostile value produces a different
// valid-looking value, which is a second bug wearing the first one's clothes.
func (id RepoID) Valid() bool { return repoIDPattern.MatchString(string(id)) }

// String returns the ID as a string.
func (id RepoID) String() string { return string(id) }

// A RunID identifies one scan of one repository: a UTC timestamp in the form
// 20060102T150405Z, a hyphen, and 8 hex characters of randomness.
//
// Treat it as opaque. The timestamp prefix means lexicographic order happens to
// be commit order, which is why [Store.Prune] can work without opening a file,
// but callers must not sort by it to establish history — two runs can share a
// second, and [Run.PrevRun] is the authoritative backward link.
type RunID string

// runIDPattern is the only shape a RunID may take; see [RepoID.Valid].
var runIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)

// Valid reports whether id is well formed.
func (id RunID) Valid() bool { return runIDPattern.MatchString(string(id)) }

// String returns the ID as a string.
func (id RunID) String() string { return string(id) }

// runIDLayout is the time layout of a [RunID]'s prefix.
const runIDLayout = "20060102T150405Z"

// Time returns the instant encoded in the ID's prefix, and whether it parsed.
// It is what lets age-based pruning avoid reading every run file.
func (id RunID) Time() (time.Time, bool) {
	if !id.Valid() {
		return time.Time{}, false
	}
	t, err := time.Parse(runIDLayout, string(id)[:len(runIDLayout)])
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Counts is a tally of findings, broken down the two ways a dashboard needs.
//
// Severities and categories with no findings are absent rather than zero, so the
// JSON stays small and a new category cannot make old records look wrong.
type Counts struct {
	Total      int                   `json:"total"`
	BySeverity map[scan.Severity]int `json:"bySeverity,omitempty"`
	ByCategory map[scan.Category]int `json:"byCategory,omitempty"`
}

// DeltaCounts summarizes what one run changed.
//
// The four numbers do not have to add up to a run's total. A finding that was
// not observed — because its scanner did not run, or the exclusions changed —
// is counted in none of them, which is the visible consequence of rules 1 and 2.
type DeltaCounts struct {
	New       int `json:"new"`
	StillOpen int `json:"stillOpen"`
	Fixed     int `json:"fixed"`
	Regressed int `json:"regressed"`
}

// Repo is one repository's history summary.
type Repo struct {
	ID   RepoID `json:"id"`
	Name string `json:"name"`

	// Path is where the repository was last scanned. It is display metadata and
	// move-detection input, never identity — see [RepoID].
	Path string `json:"path"`

	// FormerPaths are paths this repository was scanned at before it moved,
	// newest last. Kept so a user who wonders why two directories share a
	// history has an answer on the record.
	FormerPaths []string `json:"formerPaths,omitempty"`

	// Origin is the normalized git remote, when there is one.
	Origin string `json:"origin,omitempty"`

	FirstRunAt time.Time `json:"firstRunAt"`
	LastRunAt  time.Time `json:"lastRunAt"`
	LastRun    RunID     `json:"lastRun"`
	Runs       int       `json:"runs"`

	// Open counts the findings currently in an open state, from the lifecycle
	// index rather than from the last run's findings — they differ whenever a
	// run was scoped to a subset of scanners.
	Open Counts `json:"open"`

	// Missing reports that Path no longer exists on disk. A dashboard should
	// keep showing the repository — the history is still worth reading — but say
	// so, because "no new runs since March" and "this checkout is gone" are
	// different problems.
	Missing bool `json:"missing"`
}

// RunVCS is the version-control state a run was taken at.
type RunVCS struct {
	Origin string `json:"origin,omitempty"`
	Branch string `json:"branch,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// Run is the metadata of one recorded scan. The findings themselves live in the
// run's document; this is what a list view needs.
type Run struct {
	ID     RunID  `json:"id"`
	RepoID RepoID `json:"repoId"`

	// PrevRun is the run immediately before this one, or empty for the first.
	// It is the authoritative ordering; see [RunID].
	PrevRun RunID `json:"prevRun,omitempty"`

	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	DurationMS int64     `json:"durationMs"`

	Tool report.Tool `json:"tool"`
	VCS  RunVCS      `json:"vcs,omitzero"`

	// Scanners records which scanners ran, and is what makes rule 1 enforceable.
	// A run with an empty list can conclude nothing was fixed.
	Scanners []report.ScanSummary `json:"scanners,omitempty"`

	// ScopeHash is a stable hash of everything that determined which findings
	// this run could possibly have reported: the exclusion set and the
	// directory actually scanned. A change here suspends fixed-detection for
	// the run — rule 2.
	ScopeHash string `json:"scopeHash,omitempty"`

	Counts Counts      `json:"counts"`
	Delta  DeltaCounts `json:"delta"`

	// Unreadable marks a run whose file is corrupt or was written by a newer
	// Pindrop. Such a run is still listed, with Problem explaining why, and is
	// never deleted and never silently skipped: in a security product a stored
	// result quietly disappearing is worse than a broken row. Its findings are
	// treated as unknown, never as fixed.
	Unreadable bool   `json:"unreadable,omitempty"`
	Problem    string `json:"problem,omitempty"`
}

// FindingState is one fingerprint's whole life in one repository. It is the
// index that makes [scan.StatusRegressed] answerable in constant time.
type FindingState struct {
	Fingerprint string      `json:"fingerprint"`
	Status      scan.Status `json:"status"`

	// Severity, Category and Title are the last-reported values, kept so that a
	// list of open findings can be rendered and filtered without opening a
	// single run document.
	Severity scan.Severity `json:"severity"`
	Category scan.Category `json:"category"`
	Title    string        `json:"title"`

	// Scanners accumulates every adapter that has ever reported this
	// fingerprint, which is the set rule 1 intersects against the scanners that
	// ran. It only ever grows.
	Scanners []string `json:"scanners,omitempty"`

	FirstSeenAt time.Time `json:"firstSeenAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
	FirstRun    RunID     `json:"firstRun"`
	LastRun     RunID     `json:"lastRun"`

	// FixedAt and FixedRun describe the most recent time this finding was
	// concluded fixed. They survive a regression on purpose: "fixed in March,
	// back in April" is more useful than either fact alone.
	FixedAt  time.Time `json:"fixedAt,omitzero"`
	FixedRun RunID     `json:"fixedRun,omitempty"`

	Occurrences int `json:"occurrences"`
	Regressions int `json:"regressions"`
}

// clone returns a copy safe to mutate, which matters only for Scanners: the
// lifecycle fold copies the previous index rather than editing it in place, so
// that a caller holding the old map — a failed Put, a test — is unaffected.
func (s FindingState) clone() FindingState {
	if s.Scanners != nil {
		s.Scanners = append([]string(nil), s.Scanners...)
	}
	return s
}

// A Record is one completed scan, handed to [Store.Put].
//
// It carries what a [report.Document] cannot: where the scan ran, the VCS state
// at the time, wall-clock boundaries, and the exclusion hash that rule 2 needs.
type Record struct {
	// Root is the directory that was scanned. The repository is resolved from
	// it, rooting at the git work tree so that scanning a subdirectory lands in
	// the same repository as scanning the whole thing.
	Root string

	// VCS is the version-control state, as read by internal/vcs. Every field may
	// legitimately be empty.
	VCS RunVCS

	// Document is the report to store. Its RunID, Repo and Status fields are
	// filled in by Put and any values already there are replaced.
	Document report.Document

	StartedAt  time.Time
	FinishedAt time.Time

	// ScopeHash is a stable hash of everything that bounded what this run could
	// report — at minimum the exclusion set and the scanned directory.
	//
	// Both matter, and the second is easy to miss. A repository's identity is
	// its work-tree root, so `pindrop scan ./services/api` and `pindrop scan .`
	// record against the same repo; without the scanned path in this hash, the
	// narrower run would conclude that every finding outside services/api had
	// been fixed.
	//
	// Leave it empty only if the caller genuinely has no scoping concept — an
	// empty hash compares equal to an empty hash, so it never suspends
	// fixed-detection, and a caller that computes it inconsistently will
	// suspend it forever.
	ScopeHash string
}

// RunQuery filters [Store.Runs]. Its zero value returns every run, newest first.
type RunQuery struct {
	// Branch, when set, keeps only runs taken on that branch.
	Branch string

	// Since and Until bound the finish time, inclusive and exclusive
	// respectively.
	Since time.Time
	Until time.Time

	// Before pages backwards: only runs older than this one are returned. It
	// takes a run ID rather than an offset so that a new scan arriving between
	// two pages cannot shift the window.
	Before RunID

	// Limit caps the result; zero means no cap.
	Limit int
}

// FindingQuery filters findings and lifecycle states. Values within a field are
// OR'd; separate fields are AND'd. Its zero value matches everything.
type FindingQuery struct {
	Severity []scan.Severity
	Category []scan.Category
	Status   []scan.Status

	Offset int
	Limit  int
}

// DiffRequest names two runs to compare.
type DiffRequest struct {
	// Base is the run to compare against. Empty means the run immediately
	// before Head, which is the "what changed in this scan" case.
	Base RunID
	// Head is the run being examined. Empty means the repository's newest run.
	Head RunID
}

// Diff is the result of comparing two runs.
//
// A finding that was present in Base and absent from Head appears in Fixed only
// when Head could have observed it — rules 1 and 2 applied pairwise. One that
// could not be observed appears nowhere, because the honest answer about it is
// "we did not look".
type Diff struct {
	Base RunID `json:"base,omitempty"`
	Head RunID `json:"head"`

	Counts DeltaCounts `json:"counts"`

	New       []scan.Finding `json:"new"`
	StillOpen []scan.Finding `json:"stillOpen"`
	Fixed     []scan.Finding `json:"fixed"`
	Regressed []scan.Finding `json:"regressed"`
}

// Retention says how much history to keep. Its zero value keeps everything.
type Retention struct {
	// MaxRuns keeps the newest N runs.
	MaxRuns int
	// MaxAge drops runs that finished longer ago than this.
	MaxAge time.Duration
}

// keepsEverything reports whether p imposes no limit at all.
func (p Retention) keepsEverything() bool { return p.MaxRuns <= 0 && p.MaxAge <= 0 }
