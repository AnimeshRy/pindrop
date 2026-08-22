package syncclient

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

const syncStateSchema = 1

// State tracks the last synced run per local repository.
type State struct {
	Schema      int                       `json:"schema"`
	LastSynced  map[history.RepoID]string `json:"lastSyncedRun"`
}

// LoadState reads ~/.pindrop/sync-state.json.
func LoadState() (State, error) {
	path, err := toolpath.SyncStatePath()
	if err != nil {
		return State{}, err
	}

	raw, err := os.ReadFile(path) //nolint:gosec // path is under ~/.pindrop
	if err != nil {
		if os.IsNotExist(err) {
			return State{Schema: syncStateSchema, LastSynced: map[history.RepoID]string{}}, nil
		}
		return State{}, fmt.Errorf("reading sync state: %w", err)
	}

	var st State
	if err := json.Unmarshal(raw, &st); err != nil || st.Schema != syncStateSchema {
		return State{Schema: syncStateSchema, LastSynced: map[history.RepoID]string{}}, nil
	}
	if st.LastSynced == nil {
		st.LastSynced = map[history.RepoID]string{}
	}
	return st, nil
}

// SaveState writes sync checkpoints atomically.
func SaveState(st State) error {
	st.Schema = syncStateSchema
	if st.LastSynced == nil {
		st.LastSynced = map[history.RepoID]string{}
	}

	path, err := toolpath.SyncStatePath()
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding sync state: %w", err)
	}
	encoded = append(encoded, '\n')
	return toolpath.WritePrivateFile(path, encoded)
}

// RepoRequest builds the PUT /sync/repos body from a local repo summary.
func RepoRequest(repo history.Repo) PutRepoRequest {
	return PutRepoRequest{
		Name:        repo.Name,
		Origin:      repo.Origin,
		Path:        repo.Path,
		FormerPaths: repo.FormerPaths,
		LastRunID:   string(repo.LastRun),
	}
}

// RunRequest builds the PUT /sync/repos/.../runs body.
func RunRequest(run history.Run, doc report.Document, deltas []scan.Delta) (PutRunRequest, error) {
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return PutRunRequest{}, fmt.Errorf("encoding run document: %w", err)
	}

	scanners := make([]ScanSummary, 0, len(run.Scanners))
	for _, s := range run.Scanners {
		scanners = append(scanners, ScanSummary{
			Scanner:    s.Scanner,
			Findings:   s.Findings,
			DurationMS: s.DurationMS,
		})
	}

	findings := make([]Finding, 0, len(deltas))
	for _, d := range deltas {
		findings = append(findings, findingFromDelta(d))
	}

	return PutRunRequest{
		PrevRunID:   string(run.PrevRun),
		StartedAt:   run.StartedAt,
		FinishedAt:  run.FinishedAt,
		DurationMS:  run.DurationMS,
		ToolName:    run.Tool.Name,
		ToolVersion: run.Tool.Version,
		VCS: RunVCS{
			Origin: run.VCS.Origin,
			Branch: run.VCS.Branch,
			Commit: run.VCS.Commit,
		},
		Scanners:   scanners,
		ScopeHash:  run.ScopeHash,
		Counts:     countsFromHistory(run.Counts),
		Delta:      deltaFromHistory(run.Delta),
		Unreadable: run.Unreadable,
		Problem:    run.Problem,
		Document:   docBytes,
		Findings:   findings,
	}, nil
}

// StatesFromHistory converts lifecycle index rows for sync.
func StatesFromHistory(states []history.FindingState) []FindingState {
	out := make([]FindingState, 0, len(states))
	for _, s := range states {
		out = append(out, FindingState{
			Fingerprint: s.Fingerprint,
			Status:      string(s.Status),
			Severity:    string(s.Severity),
			Category:    string(s.Category),
			Title:       s.Title,
			Scanners:    append([]string(nil), s.Scanners...),
			FirstSeenAt: s.FirstSeenAt,
			LastSeenAt:  s.LastSeenAt,
			FirstRun:    string(s.FirstRun),
			LastRun:     string(s.LastRun),
			FixedAt:     s.FixedAt,
			FixedRun:    string(s.FixedRun),
			Occurrences: s.Occurrences,
			Regressions: s.Regressions,
		})
	}
	return out
}

func countsFromHistory(c history.Counts) Counts {
	out := Counts{Total: c.Total}
	if len(c.BySeverity) > 0 {
		out.BySeverity = make(map[string]int, len(c.BySeverity))
		for k, v := range c.BySeverity {
			out.BySeverity[string(k)] = v
		}
	}
	if len(c.ByCategory) > 0 {
		out.ByCategory = make(map[string]int, len(c.ByCategory))
		for k, v := range c.ByCategory {
			out.ByCategory[string(k)] = v
		}
	}
	return out
}

func deltaFromHistory(d history.DeltaCounts) DeltaCounts {
	return DeltaCounts{
		New:       d.New,
		StillOpen: d.StillOpen,
		Fixed:     d.Fixed,
		Regressed: d.Regressed,
	}
}

func findingFromDelta(d scan.Delta) Finding {
	f := d.Finding
	var refs json.RawMessage
	if len(f.References) > 0 {
		refs, _ = json.Marshal(f.References)
	}

	var pkgName, pkgVersion, pkgEco, pkgPURL string
	if f.Package != nil {
		pkgName = f.Package.Name
		pkgVersion = f.Package.Version
		pkgEco = f.Package.Ecosystem
		pkgPURL = f.Package.PURL
	}

	return Finding{
		Fingerprint:       f.Fingerprint,
		Scanner:           f.Scanner,
		Scanners:          append([]string(nil), f.Scanners...),
		RuleID:            f.RuleID,
		Aliases:           append([]string(nil), f.Aliases...),
		Category:          string(f.Category),
		Severity:          string(f.Severity),
		Title:             f.Title,
		Message:           f.Message,
		LocationPath:      f.Location.Path,
		LocationStartLine: f.Location.StartLine,
		LocationEndLine:   f.Location.EndLine,
		LocationSnippet:   f.Location.Snippet,
		PackageName:       pkgName,
		PackageVersion:    pkgVersion,
		PackageEcosystem:  pkgEco,
		PackagePURL:       pkgPURL,
		FixedIn:           f.FixedIn,
		Refs:              refs,
		Status:            string(d.Status),
	}
}

// RunsToSync filters runs to those not yet synced, returning oldest-first order.
func RunsToSync(runs []history.Run, checkpoint history.RunID) []history.Run {
	if len(runs) == 0 {
		return nil
	}

	var pending []history.Run
	for _, run := range runs {
		if checkpoint != "" && string(run.ID) <= string(checkpoint) {
			continue
		}
		pending = append(pending, run)
	}

	// Runs arrive newest-first from the store; push oldest-first for stable progress.
	for i, j := 0, len(pending)-1; i < j; i, j = i+1, j-1 {
		pending[i], pending[j] = pending[j], pending[i]
	}
	return pending
}
