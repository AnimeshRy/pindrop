package sqlite

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/history/sqlite/sqlcgen"
	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

const timeLayout = time.RFC3339Nano

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeStringSlice(raw string) []string {
	if raw == "" || raw == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func repoFromRow(r sqlcgen.Repo) history.Repo {
	return history.Repo{
		ID:          history.RepoID(r.ID),
		Name:        r.Name,
		Path:        r.Path,
		FormerPaths: decodeStringSlice(r.FormerPaths),
		Origin:      r.Origin,
		FirstRunAt:  parseTime(r.FirstRunAt),
		LastRunAt:   parseTime(r.LastRunAt),
		LastRun:     history.RunID(r.LastRunID),
	}
}

func repoToUpsert(repo history.Repo) sqlcgen.UpsertRepoParams {
	return sqlcgen.UpsertRepoParams{
		ID:          string(repo.ID),
		Name:        repo.Name,
		Path:        repo.Path,
		FormerPaths: mustJSON(repo.FormerPaths),
		Origin:      repo.Origin,
		FirstRunAt:  formatTime(repo.FirstRunAt),
		LastRunAt:   formatTime(repo.LastRunAt),
		LastRunID:   string(repo.LastRun),
	}
}

func runFromRow(r sqlcgen.Run) (history.Run, error) {
	var counts history.Counts
	if err := json.Unmarshal([]byte(r.Counts), &counts); err != nil {
		return history.Run{}, fmt.Errorf("decoding run counts: %w", err)
	}
	var delta history.DeltaCounts
	if err := json.Unmarshal([]byte(r.Delta), &delta); err != nil {
		return history.Run{}, fmt.Errorf("decoding run delta: %w", err)
	}
	var scanners []report.ScanSummary
	if err := json.Unmarshal([]byte(r.Scanners), &scanners); err != nil {
		return history.Run{}, fmt.Errorf("decoding run scanners: %w", err)
	}

	return history.Run{
		ID:         history.RunID(r.ID),
		RepoID:     history.RepoID(r.RepoID),
		PrevRun:    history.RunID(r.PrevRunID),
		StartedAt:  parseTime(r.StartedAt),
		FinishedAt: parseTime(r.FinishedAt),
		DurationMS: r.DurationMs,
		Tool:       report.Tool{Name: r.ToolName, Version: r.ToolVersion},
		VCS: history.RunVCS{
			Origin: r.VcsOrigin,
			Branch: r.VcsBranch,
			Commit: r.VcsCommit,
		},
		Scanners:   scanners,
		ScopeHash:  r.ScopeHash,
		Counts:     counts,
		Delta:      delta,
		Unreadable: r.Unreadable != 0,
		Problem:    r.Problem,
	}, nil
}

func runToInsert(run history.Run, document string) sqlcgen.InsertRunParams {
	return sqlcgen.InsertRunParams{
		ID:          string(run.ID),
		RepoID:      string(run.RepoID),
		PrevRunID:   string(run.PrevRun),
		StartedAt:   formatTime(run.StartedAt),
		FinishedAt:  formatTime(run.FinishedAt),
		DurationMs:  run.DurationMS,
		ToolName:    run.Tool.Name,
		ToolVersion: run.Tool.Version,
		VcsOrigin:   run.VCS.Origin,
		VcsBranch:   run.VCS.Branch,
		VcsCommit:   run.VCS.Commit,
		Scanners:    mustJSON(run.Scanners),
		ScopeHash:   run.ScopeHash,
		Counts:      mustJSON(run.Counts),
		Delta:       mustJSON(run.Delta),
		Unreadable:  boolToInt64(run.Unreadable),
		Problem:     run.Problem,
		Document:    document,
	}
}

func boolToInt64(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

func stateFromRow(r sqlcgen.FindingState) history.FindingState {
	return history.FindingState{
		Fingerprint: r.Fingerprint,
		Status:      scan.Status(r.Status),
		Severity:    scan.Severity(r.Severity),
		Category:    scan.Category(r.Category),
		Title:       r.Title,
		Scanners:    decodeStringSlice(r.Scanners),
		FirstSeenAt: parseTime(r.FirstSeenAt),
		LastSeenAt:  parseTime(r.LastSeenAt),
		FirstRun:    history.RunID(r.FirstRun),
		LastRun:     history.RunID(r.LastRun),
		FixedAt:     parseTime(r.FixedAt),
		FixedRun:    history.RunID(r.FixedRun),
		Occurrences: int(r.Occurrences),
		Regressions: int(r.Regressions),
	}
}

func stateToUpsert(repoID history.RepoID, st history.FindingState) sqlcgen.UpsertFindingStateParams {
	return sqlcgen.UpsertFindingStateParams{
		RepoID:      string(repoID),
		Fingerprint: st.Fingerprint,
		Status:      string(st.Status),
		Severity:    string(st.Severity),
		Category:    string(st.Category),
		Title:       st.Title,
		Scanners:    mustJSON(st.Scanners),
		FirstSeenAt: formatTime(st.FirstSeenAt),
		LastSeenAt:  formatTime(st.LastSeenAt),
		FirstRun:    string(st.FirstRun),
		LastRun:     string(st.LastRun),
		FixedAt:     formatTime(st.FixedAt),
		FixedRun:    string(st.FixedRun),
		Occurrences: int64(st.Occurrences),
		Regressions: int64(st.Regressions),
	}
}

func findingToInsert(repoID history.RepoID, runID history.RunID, f scan.Finding, status scan.Status) sqlcgen.InsertFindingParams {
	pkgName, pkgVersion, pkgEcosystem, pkgPurl := "", "", "", ""
	if f.Package != nil {
		pkgName = f.Package.Name
		pkgVersion = f.Package.Version
		pkgEcosystem = f.Package.Ecosystem
		pkgPurl = f.Package.PURL
	}
	return sqlcgen.InsertFindingParams{
		RunID:             string(runID),
		RepoID:            string(repoID),
		Fingerprint:       f.Fingerprint,
		Scanner:           f.Scanner,
		Scanners:          mustJSON(f.Scanners),
		RuleID:            f.RuleID,
		Aliases:           mustJSON(f.Aliases),
		Category:          string(f.Category),
		Severity:          string(f.Severity),
		Title:             f.Title,
		Message:           f.Message,
		LocationPath:      f.Location.Path,
		LocationStartLine: int64(f.Location.StartLine),
		LocationEndLine:   int64(f.Location.EndLine),
		LocationSnippet:   f.Location.Snippet,
		PackageName:       pkgName,
		PackageVersion:    pkgVersion,
		PackageEcosystem:  pkgEcosystem,
		PackagePurl:       pkgPurl,
		FixedIn:           f.FixedIn,
		Refs:              mustJSON(f.References),
		Status:            string(status),
	}
}

func runRecordFromRow(r sqlcgen.Run) history.RunRecord {
	return history.RunRecord{
		ID:           history.RunID(r.ID),
		DocumentJSON: r.Document,
		StartedAt:    parseTime(r.StartedAt),
		FinishedAt:   parseTime(r.FinishedAt),
		ScopeHash:    r.ScopeHash,
	}
}
