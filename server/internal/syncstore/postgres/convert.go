package postgres

import (
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/AnimeshRy/pindrop/server/internal/syncstore"
	"github.com/AnimeshRy/pindrop/server/internal/syncstore/postgres/sqlcgen"
)

func uuidFromString(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, fmt.Errorf("invalid UUID %q: %w", s, err)
	}
	return u, nil
}

func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func orgFromRow(row sqlcgen.Org) syncstore.Org {
	return syncstore.Org{
		ID:        uuidToString(row.ID),
		Name:      row.Name,
		CreatedAt: row.CreatedAt.Time,
	}
}

func repoFromRow(row sqlcgen.Repo) syncstore.Repo {
	return syncstore.Repo{
		ID:            uuidToString(row.ID),
		OrgID:         uuidToString(row.OrgID),
		Name:          row.Name,
		Origin:        row.Origin,
		LastRunID:     row.LastRunID,
		FirstSyncedAt: row.FirstSyncedAt.Time,
		LastSyncedAt:  row.LastSyncedAt.Time,
		CreatedAt:     row.CreatedAt.Time,
	}
}

func repoLinkFromRow(row sqlcgen.RepoLink) syncstore.RepoLink {
	link := syncstore.RepoLink{
		ID:            uuidToString(row.ID),
		OrgID:         uuidToString(row.OrgID),
		RepoID:        uuidToString(row.RepoID),
		Source:        syncstore.Source(row.Source),
		ExternalID:    row.ExternalID,
		Path:          row.Path,
		FirstSyncedAt: row.FirstSyncedAt.Time,
		LastSyncedAt:  row.LastSyncedAt.Time,
	}
	_ = json.Unmarshal(row.FormerPaths, &link.FormerPaths)
	if len(row.Metadata) > 0 {
		link.Metadata = json.RawMessage(row.Metadata)
	}
	return link
}

func runFromRow(row sqlcgen.Run) syncstore.Run {
	run := syncstore.Run{
		ID:          uuidToString(row.ID),
		OrgID:       uuidToString(row.OrgID),
		RepoID:      uuidToString(row.RepoID),
		Source:      syncstore.Source(row.Source),
		ClientRunID: row.ClientRunID,
		PrevRunID:   row.PrevRunID,
		StartedAt:   row.StartedAt.Time,
		FinishedAt:  row.FinishedAt.Time,
		DurationMS:  row.DurationMs,
		ToolName:    row.ToolName,
		ToolVersion: row.ToolVersion,
		VCS: syncstore.RunVCS{
			Origin: row.VcsOrigin,
			Branch: row.VcsBranch,
			Commit: row.VcsCommit,
		},
		ScopeHash:  row.ScopeHash,
		Unreadable: row.Unreadable,
		Problem:    row.Problem,
		SyncedAt:   row.SyncedAt.Time,
	}
	_ = json.Unmarshal(row.Scanners, &run.Scanners)
	_ = json.Unmarshal(row.Counts, &run.Counts)
	_ = json.Unmarshal(row.Delta, &run.Delta)
	if len(row.Document) > 0 {
		run.Document = json.RawMessage(row.Document)
	}
	return run
}

func findingFromRow(row sqlcgen.Finding) syncstore.Finding {
	return findingFromFields(findingFields{
		Fingerprint:       row.Fingerprint,
		Scanner:           row.Scanner,
		Scanners:          row.Scanners,
		RuleID:            row.RuleID,
		Aliases:           row.Aliases,
		Category:          row.Category,
		Severity:          row.Severity,
		Title:             row.Title,
		Message:           row.Message,
		LocationPath:      row.LocationPath,
		LocationStartLine: row.LocationStartLine,
		LocationEndLine:   row.LocationEndLine,
		LocationSnippet:   row.LocationSnippet,
		PackageName:       row.PackageName,
		PackageVersion:    row.PackageVersion,
		PackageEcosystem:  row.PackageEcosystem,
		PackagePurl:       row.PackagePurl,
		FixedIn:           row.FixedIn,
		Refs:              row.Refs,
		Status:            row.Status,
	})
}

func findingFromFilteredRow(row sqlcgen.ListFindingsByRunFilteredRow) syncstore.Finding {
	f := findingFromFields(findingFields{
		Fingerprint:       row.Fingerprint,
		Scanner:           row.Scanner,
		Scanners:          row.Scanners,
		RuleID:            row.RuleID,
		Aliases:           row.Aliases,
		Category:          row.Category,
		Severity:          row.Severity,
		Title:             row.Title,
		Message:           row.Message,
		LocationPath:      row.LocationPath,
		LocationStartLine: row.LocationStartLine,
		LocationEndLine:   row.LocationEndLine,
		LocationSnippet:   row.LocationSnippet,
		PackageName:       row.PackageName,
		PackageVersion:    row.PackageVersion,
		PackageEcosystem:  row.PackageEcosystem,
		PackagePurl:       row.PackagePurl,
		FixedIn:           row.FixedIn,
		Refs:              row.Refs,
		Status:            row.Status,
	})
	if row.FirstSeenAt.Valid {
		f.FirstSeenAt = row.FirstSeenAt.Time
	}
	return f
}

type findingFields struct {
	Fingerprint       string
	Scanner           string
	Scanners          []byte
	RuleID            string
	Aliases           []byte
	Category          string
	Severity          string
	Title             string
	Message           string
	LocationPath      string
	LocationStartLine int32
	LocationEndLine   int32
	LocationSnippet   string
	PackageName       string
	PackageVersion    string
	PackageEcosystem  string
	PackagePurl       string
	FixedIn           string
	Refs              []byte
	Status            string
}

func findingFromFields(row findingFields) syncstore.Finding {
	f := syncstore.Finding{
		Fingerprint:       row.Fingerprint,
		Scanner:           row.Scanner,
		RuleID:            row.RuleID,
		Category:          row.Category,
		Severity:          row.Severity,
		Title:             row.Title,
		Message:           row.Message,
		LocationPath:      row.LocationPath,
		LocationStartLine: int(row.LocationStartLine),
		LocationEndLine:   int(row.LocationEndLine),
		LocationSnippet:   row.LocationSnippet,
		PackageName:       row.PackageName,
		PackageVersion:    row.PackageVersion,
		PackageEcosystem:  row.PackageEcosystem,
		PackagePURL:       row.PackagePurl,
		FixedIn:           row.FixedIn,
		Status:            row.Status,
	}
	_ = json.Unmarshal(row.Scanners, &f.Scanners)
	_ = json.Unmarshal(row.Aliases, &f.Aliases)
	if len(row.Refs) > 0 {
		f.Refs = json.RawMessage(row.Refs)
	}
	return f
}

func stateFromRow(row sqlcgen.FindingState) syncstore.FindingState {
	st := syncstore.FindingState{
		Fingerprint: row.Fingerprint,
		Status:      row.Status,
		Severity:    row.Severity,
		Category:    row.Category,
		Title:       row.Title,
		FirstSeenAt: row.FirstSeenAt.Time,
		LastSeenAt:  row.LastSeenAt.Time,
		FirstRun:    row.FirstRun,
		LastRun:     row.LastRun,
		FixedRun:    row.FixedRun,
		Occurrences: int(row.Occurrences),
		Regressions: int(row.Regressions),
	}
	if row.FixedAt.Valid {
		st.FixedAt = row.FixedAt.Time
	}
	_ = json.Unmarshal(row.Scanners, &st.Scanners)
	return st
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func jsonOrEmpty(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return raw
}

func stringSliceJSON(paths []string) []byte {
	if paths == nil {
		return []byte("[]")
	}
	return mustJSON(paths)
}

// openCounts builds repo open totals from a count and severity breakdown rows.
func openCounts(total int64, bySeverity []sqlcgen.CountOpenFindingsBySeverityByRepoRow) syncstore.Counts {
	counts := syncstore.Counts{
		Total:      int(total),
		BySeverity: map[string]int{},
	}
	for _, row := range bySeverity {
		sev := row.Severity
		if sev == "" {
			sev = "unknown"
		}
		counts.BySeverity[sev] += int(row.Count)
	}
	if len(counts.BySeverity) == 0 {
		counts.BySeverity = nil
	}
	return counts
}

func findingFilterParams(orgID, runID pgtype.UUID, q syncstore.FindingQuery) sqlcgen.CountFindingsByRunFilteredParams {
	return sqlcgen.CountFindingsByRunFilteredParams{
		OrgID:    orgID,
		RunID:    runID,
		Severity: q.Severity,
		Category: q.Category,
		Status:   q.Status,
		Search:   q.Search,
	}
}
