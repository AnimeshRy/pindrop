// Package syncstore persists scan history synced from the CLI (and, later,
// hosted providers) for the SaaS product.
//
// The store is scoped to an organization. Callers obtain org_id from the
// orgmw middleware after JWT verification; every method takes org_id explicitly
// so tenant boundaries stay visible in signatures.
package syncstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound reports that a requested row does not exist in the caller's org.
var ErrNotFound = errors.New("not found")

// Source identifies how a repository or run was connected.
type Source string

const (
	SourceCLI       Source = "cli"
	SourceGitHub    Source = "github"
	SourceBitbucket Source = "bitbucket"
)

// Valid reports whether s is a known source value.
func (s Source) Valid() bool {
	switch s {
	case SourceCLI, SourceGitHub, SourceBitbucket:
		return true
	default:
		return false
	}
}

// Org holds a tenant organization.
type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Repo is the canonical repository row for one org.
type Repo struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"orgId"`
	Name          string    `json:"name"`
	Origin        string    `json:"origin,omitempty"`
	LastRunID     string    `json:"lastRunId,omitempty"`
	FirstSyncedAt time.Time `json:"firstSyncedAt"`
	LastSyncedAt  time.Time `json:"lastSyncedAt"`
	CreatedAt     time.Time `json:"createdAt"`

	// Derived fields populated on list/detail reads.
	Runs int   `json:"runs,omitempty"`
	Open Counts `json:"open,omitempty"`
	Links []RepoLink `json:"links,omitempty"`
}

// RepoLink records one way a canonical repo is connected.
type RepoLink struct {
	ID            string          `json:"id"`
	OrgID         string          `json:"orgId"`
	RepoID        string          `json:"repoId"`
	Source        Source          `json:"source"`
	ExternalID    string          `json:"externalId"`
	Path          string          `json:"path,omitempty"`
	FormerPaths   []string        `json:"formerPaths,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	FirstSyncedAt time.Time       `json:"firstSyncedAt"`
	LastSyncedAt  time.Time       `json:"lastSyncedAt"`
}

// LinkRepoInput upserts a connection and returns the canonical repo.
type LinkRepoInput struct {
	Source       Source
	ExternalID   string
	Name         string
	Origin       string
	Path         string
	FormerPaths  []string
	Metadata     json.RawMessage
	LastRunID    string
}

// Counts tallies findings by severity and category.
type Counts struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity,omitempty"`
	ByCategory map[string]int `json:"byCategory,omitempty"`
}

// DeltaCounts summarizes lifecycle changes for one run.
type DeltaCounts struct {
	New       int `json:"new"`
	StillOpen int `json:"stillOpen"`
	Fixed     int `json:"fixed"`
	Regressed int `json:"regressed"`
}

// RunVCS is version-control metadata for a run.
type RunVCS struct {
	Origin string `json:"origin,omitempty"`
	Branch string `json:"branch,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// ScanSummary records one scanner's contribution to a run.
type ScanSummary struct {
	Scanner    string `json:"scanner"`
	Findings   int    `json:"findings"`
	DurationMS int64  `json:"durationMs,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Run is one synced scan of a repository.
type Run struct {
	ID          string          `json:"id"`
	OrgID       string          `json:"orgId"`
	RepoID      string          `json:"repoId"`
	Source      Source          `json:"source"`
	ClientRunID string          `json:"clientRunId"`
	PrevRunID   string          `json:"prevRunId,omitempty"`
	StartedAt   time.Time       `json:"startedAt"`
	FinishedAt  time.Time       `json:"finishedAt"`
	DurationMS  int64           `json:"durationMs"`
	ToolName    string          `json:"toolName,omitempty"`
	ToolVersion string          `json:"toolVersion,omitempty"`
	VCS         RunVCS          `json:"vcs,omitempty"`
	Scanners    []ScanSummary   `json:"scanners,omitempty"`
	ScopeHash   string          `json:"scopeHash,omitempty"`
	Counts      Counts          `json:"counts"`
	Delta       DeltaCounts     `json:"delta"`
	Unreadable  bool            `json:"unreadable,omitempty"`
	Problem     string          `json:"problem,omitempty"`
	Document    json.RawMessage `json:"document,omitempty"`
	SyncedAt    time.Time       `json:"syncedAt"`
}

// PutRunInput carries one run and its normalized findings for sync.
type PutRunInput struct {
	Source      Source
	ClientRunID string
	PrevRunID   string
	StartedAt   time.Time
	FinishedAt  time.Time
	DurationMS  int64
	ToolName    string
	ToolVersion string
	VCS         RunVCS
	Scanners    []ScanSummary
	ScopeHash   string
	Counts      Counts
	Delta       DeltaCounts
	Unreadable  bool
	Problem     string
	Document    json.RawMessage
	Findings    []Finding
}

// Finding is a normalized security finding for one run.
type Finding struct {
	Fingerprint       string          `json:"fingerprint"`
	Scanner           string          `json:"scanner,omitempty"`
	Scanners          []string        `json:"scanners,omitempty"`
	RuleID            string          `json:"ruleId,omitempty"`
	Aliases           []string        `json:"aliases,omitempty"`
	Category          string          `json:"category,omitempty"`
	Severity          string          `json:"severity,omitempty"`
	Title             string          `json:"title,omitempty"`
	Message           string          `json:"message,omitempty"`
	LocationPath      string          `json:"locationPath,omitempty"`
	LocationStartLine int             `json:"locationStartLine,omitempty"`
	LocationEndLine   int             `json:"locationEndLine,omitempty"`
	LocationSnippet   string          `json:"locationSnippet,omitempty"`
	PackageName       string          `json:"packageName,omitempty"`
	PackageVersion    string          `json:"packageVersion,omitempty"`
	PackageEcosystem  string          `json:"packageEcosystem,omitempty"`
	PackagePURL       string          `json:"packagePurl,omitempty"`
	FixedIn           string          `json:"fixedIn,omitempty"`
	Refs              json.RawMessage `json:"refs,omitempty"`
	Status            string          `json:"status,omitempty"`
	// FirstSeenAt comes from the lifecycle index when available.
	FirstSeenAt time.Time `json:"firstSeenAt,omitempty"`
}

// FindingQuery filters and pages findings for one run.
type FindingQuery struct {
	RunID    string
	Severity string
	Category string
	Status   string
	Search   string
	Limit    int
	Offset   int
}

// FindingState is the lifecycle index entry for one fingerprint.
type FindingState struct {
	Fingerprint   string    `json:"fingerprint"`
	Status        string    `json:"status"`
	Severity      string    `json:"severity,omitempty"`
	Category      string    `json:"category,omitempty"`
	Title         string    `json:"title,omitempty"`
	Scanners      []string  `json:"scanners,omitempty"`
	FirstSeenAt   time.Time `json:"firstSeenAt"`
	LastSeenAt    time.Time `json:"lastSeenAt"`
	FirstRun      string    `json:"firstRun,omitempty"`
	LastRun       string    `json:"lastRun,omitempty"`
	FixedAt       time.Time `json:"fixedAt,omitempty"`
	FixedRun      string    `json:"fixedRun,omitempty"`
	Occurrences   int       `json:"occurrences"`
	Regressions   int       `json:"regressions"`
}

// Store persists synced scan history for the SaaS product.
type Store interface {
	// EnsurePersonalOrg creates the user row and a 1:1 personal org if needed.
	EnsurePersonalOrg(ctx context.Context, userID, email string) (Org, error)

	// LinkRepo upserts a repo_link and the canonical repo, matching by origin when set.
	LinkRepo(ctx context.Context, orgID string, in LinkRepoInput) (Repo, RepoLink, error)

	// PutRun upserts one run and replaces its findings (idempotent).
	PutRun(ctx context.Context, orgID, repoID string, in PutRunInput) (Run, error)

	// PutStates replaces the lifecycle index for a repo wholesale.
	PutStates(ctx context.Context, orgID, repoID string, states []FindingState) error

	// ListRepos returns canonical repos for an org, optionally filtered by link source.
	ListRepos(ctx context.Context, orgID string, source Source) ([]Repo, error)

	// GetRepo returns one repo with its links.
	GetRepo(ctx context.Context, orgID, repoID string) (Repo, error)

	// ListRuns returns runs for a repo, newest first.
	ListRuns(ctx context.Context, orgID, repoID string) ([]Run, error)

	// GetRun returns one run by server UUID or CLI client run id (repo.lastRunId).
	GetRun(ctx context.Context, orgID, repoID, runID string) (Run, error)

	// ListRunFindings returns findings for one run, filtered and paginated.
	ListRunFindings(ctx context.Context, orgID string, q FindingQuery) ([]Finding, int, error)

	// ListStates returns the lifecycle index for a repo.
	ListStates(ctx context.Context, orgID, repoID string) ([]FindingState, error)

	// ResolveRepoLink looks up a repo by its external link id (e.g. CLI client repo id).
	ResolveRepoLink(ctx context.Context, orgID string, source Source, externalID string) (Repo, RepoLink, error)

	// Close releases resources.
	Close() error
}
