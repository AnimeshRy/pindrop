package postgres_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/AnimeshRy/pindrop/server/internal/syncstore"
	pgstore "github.com/AnimeshRy/pindrop/server/internal/syncstore/postgres"
)

func openTestStore(t *testing.T) *pgstore.Store {
	t.Helper()
	ctx := context.Background()

	if os.Getenv("SKIP_TESTCONTAINERS") == "1" {
		t.Skip("SKIP_TESTCONTAINERS=1")
	}

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("pindrop_test"),
		postgres.WithUsername("pindrop"),
		postgres.WithPassword("pindrop"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		),
	)
	if err != nil {
		t.Skipf("docker not available for postgres testcontainers: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	store, err := pgstore.Open(ctx, connStr)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestEnsurePersonalOrg(t *testing.T) {
	t.Parallel()
	store := openTestStore(t)
	ctx := context.Background()

	org, err := store.EnsurePersonalOrg(ctx, "550e8400-e29b-41d4-a716-446655440000", "dev@example.com")
	if err != nil {
		t.Fatalf("EnsurePersonalOrg: %v", err)
	}
	if org.ID == "" {
		t.Fatal("expected org id")
	}
	if org.Name == "" {
		t.Fatal("expected org name")
	}

	org2, err := store.EnsurePersonalOrg(ctx, "550e8400-e29b-41d4-a716-446655440000", "dev@example.com")
	if err != nil {
		t.Fatalf("EnsurePersonalOrg second call: %v", err)
	}
	if org2.ID != org.ID {
		t.Fatalf("org id changed on second call: %q vs %q", org2.ID, org.ID)
	}
}

func TestLinkRepoOriginDedup(t *testing.T) {
	t.Parallel()
	store := openTestStore(t)
	ctx := context.Background()

	org, err := store.EnsurePersonalOrg(ctx, "550e8400-e29b-41d4-a716-446655440001", "a@example.com")
	if err != nil {
		t.Fatalf("EnsurePersonalOrg: %v", err)
	}

	repo1, link1, err := store.LinkRepo(ctx, org.ID, syncstore.LinkRepoInput{
		Source:     syncstore.SourceCLI,
		ExternalID: "r_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Name:       "pindrop",
		Origin:     "https://github.com/example/pindrop.git",
		Path:       "/home/dev/pindrop",
	})
	if err != nil {
		t.Fatalf("LinkRepo laptop A: %v", err)
	}

	repo2, link2, err := store.LinkRepo(ctx, org.ID, syncstore.LinkRepoInput{
		Source:     syncstore.SourceCLI,
		ExternalID: "r_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Name:       "pindrop",
		Origin:     "https://github.com/example/pindrop.git",
		Path:       "/Users/dev/pindrop",
	})
	if err != nil {
		t.Fatalf("LinkRepo laptop B: %v", err)
	}

	if repo1.ID != repo2.ID {
		t.Fatalf("expected same canonical repo, got %q and %q", repo1.ID, repo2.ID)
	}
	if link1.ID == link2.ID {
		t.Fatal("expected distinct repo links")
	}
}

func TestPutRunFindingsAndStates(t *testing.T) {
	t.Parallel()
	store := openTestStore(t)
	ctx := context.Background()

	org, err := store.EnsurePersonalOrg(ctx, "550e8400-e29b-41d4-a716-446655440002", "b@example.com")
	if err != nil {
		t.Fatalf("EnsurePersonalOrg: %v", err)
	}

	repo, _, err := store.LinkRepo(ctx, org.ID, syncstore.LinkRepoInput{
		Source:     syncstore.SourceCLI,
		ExternalID: "r_cccccccccccccccccccccccccccccccc",
		Name:       "fixture",
		Path:       "/tmp/fixture",
	})
	if err != nil {
		t.Fatalf("LinkRepo: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	run, err := store.PutRun(ctx, org.ID, repo.ID, syncstore.PutRunInput{
		Source:      syncstore.SourceCLI,
		ClientRunID:   "20260101T120000Z-deadbeef",
		StartedAt:     now.Add(-time.Minute),
		FinishedAt:    now,
		DurationMS:    60000,
		ToolName:      "pindrop",
		ToolVersion:   "0.1.0",
		Counts:        syncstore.Counts{Total: 1},
		Delta:         syncstore.DeltaCounts{New: 1},
		Document:    json.RawMessage(`{"findings":[]}`),
		Findings: []syncstore.Finding{
			{
				Fingerprint: "fp-test",
				Scanner:     "trivy",
				Category:    "vulnerability",
				Severity:    "high",
				Title:       "Test CVE",
				Status:      "new",
			},
		},
	})
	if err != nil {
		t.Fatalf("PutRun: %v", err)
	}
	if run.ID == "" {
		t.Fatal("expected run id")
	}

	findings, total, err := store.ListRunFindings(ctx, org.ID, syncstore.FindingQuery{
		RunID: run.ID,
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("ListRunFindings: %v", err)
	}
	if total != 1 || len(findings) != 1 || findings[0].Fingerprint != "fp-test" {
		t.Fatalf("findings = %+v total=%d, want one fp-test", findings, total)
	}

	states := []syncstore.FindingState{{
		Fingerprint: "fp-test",
		Status:      "new",
		Severity:    "high",
		Category:    "vulnerability",
		Title:       "Test CVE",
		FirstSeenAt: now,
		LastSeenAt:  now,
		FirstRun:    "20260101T120000Z-deadbeef",
		LastRun:     "20260101T120000Z-deadbeef",
		Occurrences: 1,
	}}
	if err := store.PutStates(ctx, org.ID, repo.ID, states); err != nil {
		t.Fatalf("PutStates: %v", err)
	}

	gotStates, err := store.ListStates(ctx, org.ID, repo.ID)
	if err != nil {
		t.Fatalf("ListStates: %v", err)
	}
	if len(gotStates) != 1 {
		t.Fatalf("states len = %d, want 1", len(gotStates))
	}

	repos, err := store.ListRepos(ctx, org.ID, syncstore.SourceCLI)
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("repos len = %d, want 1", len(repos))
	}
	if repos[0].Open.Total != 1 {
		t.Fatalf("open total = %d, want 1", repos[0].Open.Total)
	}
	if repos[0].Open.BySeverity["high"] != 1 {
		t.Fatalf("open bySeverity = %+v, want high=1", repos[0].Open.BySeverity)
	}
}

func TestGetRunByClientRunID(t *testing.T) {
	t.Parallel()
	store := openTestStore(t)
	ctx := context.Background()

	org, err := store.EnsurePersonalOrg(ctx, "550e8400-e29b-41d4-a716-446655440003", "c@example.com")
	if err != nil {
		t.Fatalf("EnsurePersonalOrg: %v", err)
	}

	repo, _, err := store.LinkRepo(ctx, org.ID, syncstore.LinkRepoInput{
		Source:     syncstore.SourceCLI,
		ExternalID: "r_dddddddddddddddddddddddddddddddd",
		Name:       "backfill",
		Path:       "/tmp/backfill",
	})
	if err != nil {
		t.Fatalf("LinkRepo: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	newerClientID := "20260201T120000Z-11111111"
	olderClientID := "20260101T120000Z-22222222"

	newerRun, err := store.PutRun(ctx, org.ID, repo.ID, syncstore.PutRunInput{
		Source:     syncstore.SourceCLI,
		ClientRunID: newerClientID,
		StartedAt:  now.Add(-time.Minute),
		FinishedAt: now,
		DurationMS: 60000,
		Counts:     syncstore.Counts{Total: 2},
		Delta:      syncstore.DeltaCounts{New: 2},
		Document:   json.RawMessage(`{"findings":[]}`),
	})
	if err != nil {
		t.Fatalf("PutRun newer: %v", err)
	}

	olderRun, err := store.PutRun(ctx, org.ID, repo.ID, syncstore.PutRunInput{
		Source:     syncstore.SourceCLI,
		ClientRunID: olderClientID,
		StartedAt:  now.Add(-3 * time.Hour),
		FinishedAt: now.Add(-2 * time.Hour),
		DurationMS: 60000,
		Counts:     syncstore.Counts{Total: 1},
		Delta:      syncstore.DeltaCounts{New: 1},
		Document:   json.RawMessage(`{"findings":[]}`),
	})
	if err != nil {
		t.Fatalf("PutRun older: %v", err)
	}

	gotRepo, err := store.GetRepo(ctx, org.ID, repo.ID)
	if err != nil {
		t.Fatalf("GetRepo: %v", err)
	}
	if gotRepo.LastRunID != olderClientID {
		t.Fatalf("LastRunID = %q, want %q", gotRepo.LastRunID, olderClientID)
	}

	runs, err := store.ListRuns(ctx, org.ID, repo.ID)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 2 || runs[0].ClientRunID != newerClientID {
		t.Fatalf("ListRuns[0] = %+v, want newest finishedAt first", runs[0])
	}

	byClientID, err := store.GetRun(ctx, org.ID, repo.ID, olderClientID)
	if err != nil {
		t.Fatalf("GetRun by client id: %v", err)
	}
	if byClientID.ID != olderRun.ID {
		t.Fatalf("GetRun client id returned %q, want %q", byClientID.ID, olderRun.ID)
	}

	byServerID, err := store.GetRun(ctx, org.ID, repo.ID, newerRun.ID)
	if err != nil {
		t.Fatalf("GetRun by server id: %v", err)
	}
	if byServerID.ID != newerRun.ID {
		t.Fatalf("GetRun server id returned %q, want %q", byServerID.ID, newerRun.ID)
	}
}
