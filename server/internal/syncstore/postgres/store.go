package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/AnimeshRy/pindrop/server/internal/syncstore"
	"github.com/AnimeshRy/pindrop/server/internal/syncstore/postgres/sqlcgen"
)

// Store is a [syncstore.Store] backed by Postgres.
type Store struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

// Open connects to Postgres, runs migrations, and returns a Store.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	// Goose expects database/sql; stdlib adapts pgxpool's config.
	cfg := pool.Config().ConnConfig
	db := stdlib.OpenDB(*cfg)
	defer db.Close()

	if err := RunMigrations(ctx, db); err != nil {
		pool.Close()
		return nil, err
	}

	return &Store{
		pool: pool,
		q:    sqlcgen.New(pool),
	}, nil
}

// Close releases the connection pool.
func (s *Store) Close() error {
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

// EnsurePersonalOrg creates the user and a 1:1 personal org when missing.
func (s *Store) EnsurePersonalOrg(ctx context.Context, userID, email string) (syncstore.Org, error) {
	uid, err := uuidFromString(userID)
	if err != nil {
		return syncstore.Org{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return syncstore.Org{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := s.q.WithTx(tx)

	if err := q.UpsertUser(ctx, sqlcgen.UpsertUserParams{
		ID:    uid,
		Email: email,
	}); err != nil {
		return syncstore.Org{}, fmt.Errorf("upserting user: %w", err)
	}

	row, err := q.GetPersonalOrgForUser(ctx, uid)
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return syncstore.Org{}, err
		}
		return orgFromRow(row), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return syncstore.Org{}, fmt.Errorf("looking up personal org: %w", err)
	}

	name := personalOrgName(email)
	orgRow, err := q.CreateOrg(ctx, name)
	if err != nil {
		return syncstore.Org{}, fmt.Errorf("creating org: %w", err)
	}
	if err := q.AddOrgMember(ctx, sqlcgen.AddOrgMemberParams{
		OrgID:  orgRow.ID,
		UserID: uid,
		Role:   "owner",
	}); err != nil {
		return syncstore.Org{}, fmt.Errorf("adding org member: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return syncstore.Org{}, err
	}
	return orgFromRow(orgRow), nil
}

func personalOrgName(email string) string {
	if email != "" {
		return email + "'s workspace"
	}
	return "Personal workspace"
}

// LinkRepo upserts a repo_link and canonical repo, matching by origin when set.
func (s *Store) LinkRepo(ctx context.Context, orgID string, in syncstore.LinkRepoInput) (syncstore.Repo, syncstore.RepoLink, error) {
	if !in.Source.Valid() {
		return syncstore.Repo{}, syncstore.RepoLink{}, fmt.Errorf("invalid source %q", in.Source)
	}
	if in.ExternalID == "" {
		return syncstore.Repo{}, syncstore.RepoLink{}, errors.New("external id is required")
	}
	if in.Name == "" {
		return syncstore.Repo{}, syncstore.RepoLink{}, errors.New("repo name is required")
	}

	oid, err := uuidFromString(orgID)
	if err != nil {
		return syncstore.Repo{}, syncstore.RepoLink{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return syncstore.Repo{}, syncstore.RepoLink{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := s.q.WithTx(tx)

	var repoRow sqlcgen.Repo
	if in.Origin != "" {
		existing, err := q.GetRepoByOrigin(ctx, sqlcgen.GetRepoByOriginParams{
			OrgID:  oid,
			Origin: in.Origin,
		})
		if err == nil {
			repoRow = existing
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return syncstore.Repo{}, syncstore.RepoLink{}, err
		}
	}

	if !repoRow.ID.Valid {
		repoRow, err = q.InsertRepo(ctx, sqlcgen.InsertRepoParams{
			OrgID:     oid,
			Name:      in.Name,
			Origin:    in.Origin,
			LastRunID: in.LastRunID,
		})
		if err != nil {
			return syncstore.Repo{}, syncstore.RepoLink{}, fmt.Errorf("inserting repo: %w", err)
		}
	} else {
		if err := q.UpdateRepoSynced(ctx, sqlcgen.UpdateRepoSyncedParams{
			OrgID:     oid,
			ID:        repoRow.ID,
			Name:      in.Name,
			Origin:    in.Origin,
			LastRunID: in.LastRunID,
		}); err != nil {
			return syncstore.Repo{}, syncstore.RepoLink{}, err
		}
		repoRow, err = q.GetRepoByID(ctx, sqlcgen.GetRepoByIDParams{
			OrgID: oid,
			ID:    repoRow.ID,
		})
		if err != nil {
			return syncstore.Repo{}, syncstore.RepoLink{}, err
		}
	}

	linkRow, err := q.UpsertRepoLink(ctx, sqlcgen.UpsertRepoLinkParams{
		OrgID:        oid,
		RepoID:       repoRow.ID,
		Source:       string(in.Source),
		ExternalID:   in.ExternalID,
		Path:         in.Path,
		FormerPaths:  stringSliceJSON(in.FormerPaths),
		Metadata:     jsonOrEmpty(in.Metadata),
	})
	if err != nil {
		return syncstore.Repo{}, syncstore.RepoLink{}, fmt.Errorf("upserting repo link: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return syncstore.Repo{}, syncstore.RepoLink{}, err
	}
	return repoFromRow(repoRow), repoLinkFromRow(linkRow), nil
}

// PutRun upserts one run and replaces its findings.
func (s *Store) PutRun(ctx context.Context, orgID, repoID string, in syncstore.PutRunInput) (syncstore.Run, error) {
	if !in.Source.Valid() {
		return syncstore.Run{}, fmt.Errorf("invalid source %q", in.Source)
	}
	if in.ClientRunID == "" {
		return syncstore.Run{}, errors.New("client run id is required")
	}

	oid, err := uuidFromString(orgID)
	if err != nil {
		return syncstore.Run{}, err
	}
	rid, err := uuidFromString(repoID)
	if err != nil {
		return syncstore.Run{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return syncstore.Run{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := s.q.WithTx(tx)

	// Verify repo belongs to org before writing child rows.
	if _, err := q.GetRepoByID(ctx, sqlcgen.GetRepoByIDParams{OrgID: oid, ID: rid}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return syncstore.Run{}, syncstore.ErrNotFound
		}
		return syncstore.Run{}, err
	}

	runRow, err := q.UpsertRun(ctx, sqlcgen.UpsertRunParams{
		OrgID:        oid,
		RepoID:       rid,
		Source:       string(in.Source),
		ClientRunID:  in.ClientRunID,
		PrevRunID:    in.PrevRunID,
		StartedAt:    pgTimestamptz(in.StartedAt),
		FinishedAt:   pgTimestamptz(in.FinishedAt),
		DurationMs:   in.DurationMS,
		ToolName:     in.ToolName,
		ToolVersion:  in.ToolVersion,
		VcsOrigin:    in.VCS.Origin,
		VcsBranch:    in.VCS.Branch,
		VcsCommit:    in.VCS.Commit,
		Scanners:     mustJSON(in.Scanners),
		ScopeHash:    in.ScopeHash,
		Counts:       mustJSON(in.Counts),
		Delta:        mustJSON(in.Delta),
		Unreadable:   in.Unreadable,
		Problem:      in.Problem,
		Document:     jsonOrEmpty(in.Document),
	})
	if err != nil {
		return syncstore.Run{}, fmt.Errorf("upserting run: %w", err)
	}

	if err := q.DeleteFindingsByRun(ctx, sqlcgen.DeleteFindingsByRunParams{
		OrgID: oid,
		RunID: runRow.ID,
	}); err != nil {
		return syncstore.Run{}, err
	}

	for _, f := range in.Findings {
		if err := q.InsertFinding(ctx, sqlcgen.InsertFindingParams{
			OrgID:             oid,
			RepoID:            rid,
			RunID:             runRow.ID,
			Fingerprint:       f.Fingerprint,
			Scanner:           f.Scanner,
			Scanners:          mustJSON(f.Scanners),
			RuleID:            f.RuleID,
			Aliases:           mustJSON(f.Aliases),
			Category:          f.Category,
			Severity:          f.Severity,
			Title:             f.Title,
			Message:           f.Message,
			LocationPath:      f.LocationPath,
			LocationStartLine: int32(f.LocationStartLine),
			LocationEndLine:   int32(f.LocationEndLine),
			LocationSnippet:   f.LocationSnippet,
			PackageName:       f.PackageName,
			PackageVersion:    f.PackageVersion,
			PackageEcosystem:  f.PackageEcosystem,
			PackagePurl:       f.PackagePURL,
			FixedIn:           f.FixedIn,
			Refs:              jsonOrEmpty(f.Refs),
			Status:            f.Status,
		}); err != nil {
			return syncstore.Run{}, err
		}
	}

	if err := q.TouchRepoLastRun(ctx, sqlcgen.TouchRepoLastRunParams{
		OrgID:     oid,
		ID:        rid,
		LastRunID: in.ClientRunID,
	}); err != nil {
		return syncstore.Run{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return syncstore.Run{}, err
	}
	return runFromRow(runRow), nil
}

// PutStates replaces the lifecycle index for a repo.
func (s *Store) PutStates(ctx context.Context, orgID, repoID string, states []syncstore.FindingState) error {
	oid, err := uuidFromString(orgID)
	if err != nil {
		return err
	}
	rid, err := uuidFromString(repoID)
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := s.q.WithTx(tx)

	if _, err := q.GetRepoByID(ctx, sqlcgen.GetRepoByIDParams{OrgID: oid, ID: rid}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return syncstore.ErrNotFound
		}
		return err
	}

	if err := q.DeleteFindingStatesByRepo(ctx, sqlcgen.DeleteFindingStatesByRepoParams{
		OrgID:  oid,
		RepoID: rid,
	}); err != nil {
		return err
	}

	for _, st := range states {
		var fixedAt pgtype.Timestamptz
		if !st.FixedAt.IsZero() {
			fixedAt = pgTimestamptz(st.FixedAt)
		}
		if err := q.InsertFindingState(ctx, sqlcgen.InsertFindingStateParams{
			OrgID:       oid,
			RepoID:      rid,
			Fingerprint: st.Fingerprint,
			Status:      st.Status,
			Severity:    st.Severity,
			Category:    st.Category,
			Title:       st.Title,
			Scanners:    mustJSON(st.Scanners),
			FirstSeenAt: pgTimestamptz(st.FirstSeenAt),
			LastSeenAt:  pgTimestamptz(st.LastSeenAt),
			FirstRun:    st.FirstRun,
			LastRun:     st.LastRun,
			FixedAt:     fixedAt,
			FixedRun:    st.FixedRun,
			Occurrences: int32(st.Occurrences),
			Regressions: int32(st.Regressions),
		}); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// ListRepos returns repos for an org, optionally filtered by link source.
func (s *Store) ListRepos(ctx context.Context, orgID string, source syncstore.Source) ([]syncstore.Repo, error) {
	oid, err := uuidFromString(orgID)
	if err != nil {
		return nil, err
	}

	rows, err := s.q.ListReposByOrg(ctx, oid)
	if err != nil {
		return nil, err
	}

	allLinks, err := s.q.ListRepoLinksByOrg(ctx, oid)
	if err != nil {
		return nil, err
	}
	linksByRepo := map[string][]syncstore.RepoLink{}
	for _, l := range allLinks {
		link := repoLinkFromRow(l)
		if source != "" && link.Source != source {
			continue
		}
		linksByRepo[link.RepoID] = append(linksByRepo[link.RepoID], link)
	}

	out := make([]syncstore.Repo, 0, len(rows))
	for _, row := range rows {
		repo := repoFromRow(row)
		repo.Links = linksByRepo[repo.ID]
		if source != "" && len(repo.Links) == 0 {
			continue
		}
		runCount, err := s.q.CountRunsByRepo(ctx, sqlcgen.CountRunsByRepoParams{
			OrgID:  oid,
			RepoID: row.ID,
		})
		if err != nil {
			return nil, err
		}
		repo.Runs = int(runCount)
		openCount, err := s.q.CountOpenFindingsByRepo(ctx, sqlcgen.CountOpenFindingsByRepoParams{
			OrgID:  oid,
			RepoID: row.ID,
		})
		if err != nil {
			return nil, err
		}
		bySeverity, err := s.q.CountOpenFindingsBySeverityByRepo(ctx, sqlcgen.CountOpenFindingsBySeverityByRepoParams{
			OrgID:  oid,
			RepoID: row.ID,
		})
		if err != nil {
			return nil, err
		}
		repo.Open = openCounts(openCount, bySeverity)
		out = append(out, repo)
	}
	return out, nil
}

// GetRepo returns one repo with its links.
func (s *Store) GetRepo(ctx context.Context, orgID, repoID string) (syncstore.Repo, error) {
	oid, err := uuidFromString(orgID)
	if err != nil {
		return syncstore.Repo{}, err
	}
	rid, err := uuidFromString(repoID)
	if err != nil {
		return syncstore.Repo{}, err
	}

	row, err := s.q.GetRepoByID(ctx, sqlcgen.GetRepoByIDParams{OrgID: oid, ID: rid})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return syncstore.Repo{}, syncstore.ErrNotFound
		}
		return syncstore.Repo{}, err
	}

	repo := repoFromRow(row)
	links, err := s.q.ListRepoLinksByRepo(ctx, sqlcgen.ListRepoLinksByRepoParams{
		OrgID:  oid,
		RepoID: rid,
	})
	if err != nil {
		return syncstore.Repo{}, err
	}
	for _, l := range links {
		repo.Links = append(repo.Links, repoLinkFromRow(l))
	}
	runCount, err := s.q.CountRunsByRepo(ctx, sqlcgen.CountRunsByRepoParams{OrgID: oid, RepoID: rid})
	if err != nil {
		return syncstore.Repo{}, err
	}
	repo.Runs = int(runCount)
	openCount, err := s.q.CountOpenFindingsByRepo(ctx, sqlcgen.CountOpenFindingsByRepoParams{
		OrgID:  oid,
		RepoID: rid,
	})
	if err != nil {
		return syncstore.Repo{}, err
	}
	bySeverity, err := s.q.CountOpenFindingsBySeverityByRepo(ctx, sqlcgen.CountOpenFindingsBySeverityByRepoParams{
		OrgID:  oid,
		RepoID: rid,
	})
	if err != nil {
		return syncstore.Repo{}, err
	}
	repo.Open = openCounts(openCount, bySeverity)
	return repo, nil
}

// ListRuns returns runs for a repo, newest first.
func (s *Store) ListRuns(ctx context.Context, orgID, repoID string) ([]syncstore.Run, error) {
	oid, err := uuidFromString(orgID)
	if err != nil {
		return nil, err
	}
	rid, err := uuidFromString(repoID)
	if err != nil {
		return nil, err
	}

	rows, err := s.q.ListRunsByRepo(ctx, sqlcgen.ListRunsByRepoParams{OrgID: oid, RepoID: rid})
	if err != nil {
		return nil, err
	}
	out := make([]syncstore.Run, 0, len(rows))
	for _, row := range rows {
		out = append(out, runFromRow(row))
	}
	return out, nil
}

// GetRun returns one run by server UUID or CLI client run id (repo.lastRunId).
func (s *Store) GetRun(ctx context.Context, orgID, repoID, runID string) (syncstore.Run, error) {
	oid, err := uuidFromString(orgID)
	if err != nil {
		return syncstore.Run{}, err
	}
	rid, err := uuidFromString(repoID)
	if err != nil {
		return syncstore.Run{}, err
	}

	if runUUID, err := uuidFromString(runID); err == nil {
		row, err := s.q.GetRunByID(ctx, sqlcgen.GetRunByIDParams{
			OrgID:  oid,
			RepoID: rid,
			ID:     runUUID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return syncstore.Run{}, syncstore.ErrNotFound
			}
			return syncstore.Run{}, err
		}
		return runFromRow(row), nil
	}

	row, err := s.q.GetRunByClientID(ctx, sqlcgen.GetRunByClientIDParams{
		RepoID:      rid,
		ClientRunID: runID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return syncstore.Run{}, syncstore.ErrNotFound
		}
		return syncstore.Run{}, err
	}
	run := runFromRow(row)
	if run.OrgID != orgID {
		return syncstore.Run{}, syncstore.ErrNotFound
	}
	return run, nil
}

// ListRunFindings returns findings for one run, filtered and paginated.
func (s *Store) ListRunFindings(ctx context.Context, orgID string, q syncstore.FindingQuery) ([]syncstore.Finding, int, error) {
	oid, err := uuidFromString(orgID)
	if err != nil {
		return nil, 0, err
	}
	runUUID, err := uuidFromString(q.RunID)
	if err != nil {
		return nil, 0, err
	}

	filter := findingFilterParams(oid, runUUID, q)
	total, err := s.q.CountFindingsByRunFiltered(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	rows, err := s.q.ListFindingsByRunFiltered(ctx, sqlcgen.ListFindingsByRunFilteredParams{
		OrgID:      oid,
		RunID:      runUUID,
		Severity:   q.Severity,
		Category:   q.Category,
		Status:     q.Status,
		Search:     q.Search,
		PageLimit:  int32(limit),
		PageOffset: int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]syncstore.Finding, 0, len(rows))
	for _, row := range rows {
		out = append(out, findingFromFilteredRow(row))
	}
	return out, int(total), nil
}

// ListStates returns the lifecycle index for a repo.
func (s *Store) ListStates(ctx context.Context, orgID, repoID string) ([]syncstore.FindingState, error) {
	oid, err := uuidFromString(orgID)
	if err != nil {
		return nil, err
	}
	rid, err := uuidFromString(repoID)
	if err != nil {
		return nil, err
	}

	rows, err := s.q.ListFindingStatesByRepo(ctx, sqlcgen.ListFindingStatesByRepoParams{
		OrgID:  oid,
		RepoID: rid,
	})
	if err != nil {
		return nil, err
	}
	out := make([]syncstore.FindingState, 0, len(rows))
	for _, row := range rows {
		out = append(out, stateFromRow(row))
	}
	return out, nil
}

// ResolveRepoLink looks up a canonical repo by link external id.
func (s *Store) ResolveRepoLink(ctx context.Context, orgID string, source syncstore.Source, externalID string) (syncstore.Repo, syncstore.RepoLink, error) {
	oid, err := uuidFromString(orgID)
	if err != nil {
		return syncstore.Repo{}, syncstore.RepoLink{}, err
	}

	linkRow, err := s.q.GetRepoLinkByExternal(ctx, sqlcgen.GetRepoLinkByExternalParams{
		OrgID:      oid,
		Source:     string(source),
		ExternalID: externalID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return syncstore.Repo{}, syncstore.RepoLink{}, syncstore.ErrNotFound
		}
		return syncstore.Repo{}, syncstore.RepoLink{}, err
	}

	repoRow, err := s.q.GetRepoByID(ctx, sqlcgen.GetRepoByIDParams{
		OrgID: oid,
		ID:    linkRow.RepoID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return syncstore.Repo{}, syncstore.RepoLink{}, syncstore.ErrNotFound
		}
		return syncstore.Repo{}, syncstore.RepoLink{}, err
	}
	return repoFromRow(repoRow), repoLinkFromRow(linkRow), nil
}

func pgTimestamptz(t time.Time) pgtype.Timestamptz {
	var ts pgtype.Timestamptz
	if t.IsZero() {
		t = time.Now().UTC()
	}
	_ = ts.Scan(t)
	return ts
}
