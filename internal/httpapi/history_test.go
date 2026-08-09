package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/httpapi"
	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// Well-formed identifiers. Tests use these constants rather than literals so
// that a change to the ID grammar fails in one place.
const (
	repoA = "r_00000000000000000000000000000001"
	repoB = "r_00000000000000000000000000000002"
	run1  = "20260101T120000Z-aaaaaaaa"
	run2  = "20260102T120000Z-bbbbbbbb"
)

// fakeStore is an in-memory [history.Store].
//
// The API is tested against a fake rather than a real JSON store on purpose:
// these tests are about routing, validation, query parsing and status mapping,
// and a filesystem store would make every one of them also a test of the
// store's own file layout. It records the last query it was handed, which is
// how the tests assert that filters are pushed down rather than applied in the
// handler.
type fakeStore struct {
	repos    []history.Repo
	runs     map[history.RepoID][]history.Run
	deltas   map[history.RunID][]scan.Delta
	states   []history.FindingState
	diff     history.Diff
	docs     map[history.RunID]report.Document
	err      error // returned by every method when non-nil
	lastFind history.FindingQuery
	lastRun  history.RunQuery
}

func (s *fakeStore) Put(context.Context, history.Record) (history.Run, error) {
	return history.Run{}, s.err
}

func (s *fakeStore) Repos(context.Context) ([]history.Repo, error) {
	return s.repos, s.err
}

func (s *fakeStore) RepoByID(_ context.Context, id history.RepoID) (history.Repo, error) {
	if s.err != nil {
		return history.Repo{}, s.err
	}
	for _, r := range s.repos {
		if r.ID == id {
			return r, nil
		}
	}
	return history.Repo{}, fmt.Errorf("no repository %s: %w", id, history.ErrNotFound)
}

func (s *fakeStore) RepoByPath(context.Context, string) (history.Repo, error) {
	if s.err != nil {
		return history.Repo{}, s.err
	}
	if len(s.repos) == 0 {
		return history.Repo{}, fmt.Errorf("no history: %w", history.ErrNotFound)
	}
	return s.repos[0], nil
}

func (s *fakeStore) Runs(_ context.Context, id history.RepoID, q history.RunQuery) ([]history.Run, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.lastRun = q

	runs, ok := s.runs[id]
	if !ok {
		return nil, fmt.Errorf("no repository %s: %w", id, history.ErrNotFound)
	}
	if q.Branch != "" {
		runs = slices.DeleteFunc(slices.Clone(runs), func(r history.Run) bool {
			return r.VCS.Branch != q.Branch
		})
	}
	if q.Limit > 0 && q.Limit < len(runs) {
		runs = runs[:q.Limit]
	}
	return runs, nil
}

func (s *fakeStore) RunByID(_ context.Context, id history.RepoID, run history.RunID) (history.Run, error) {
	if s.err != nil {
		return history.Run{}, s.err
	}
	for _, r := range s.runs[id] {
		if r.ID == run {
			return r, nil
		}
	}
	return history.Run{}, fmt.Errorf("no run %s: %w", run, history.ErrNotFound)
}

func (s *fakeStore) Findings(
	_ context.Context, id history.RepoID, run history.RunID, q history.FindingQuery,
) ([]scan.Delta, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.lastFind = q

	if _, err := s.RunByID(context.Background(), id, run); err != nil {
		return nil, err
	}
	return s.deltas[run], nil
}

func (s *fakeStore) Document(
	_ context.Context, _ history.RepoID, run history.RunID,
) (report.Document, error) {
	if s.err != nil {
		return report.Document{}, s.err
	}
	doc, ok := s.docs[run]
	if !ok {
		return report.Document{}, fmt.Errorf("no run %s: %w", run, history.ErrNotFound)
	}
	return doc, nil
}

func (s *fakeStore) States(
	_ context.Context, id history.RepoID, q history.FindingQuery,
) ([]history.FindingState, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.lastFind = q

	if _, err := s.RepoByID(context.Background(), id); err != nil {
		return nil, err
	}
	return s.states, nil
}

func (s *fakeStore) DiffRuns(
	_ context.Context, id history.RepoID, req history.DiffRequest,
) (history.Diff, error) {
	if s.err != nil {
		return history.Diff{}, s.err
	}
	if _, err := s.RunByID(context.Background(), id, req.Head); err != nil {
		return history.Diff{}, err
	}

	diff := s.diff
	diff.Head = req.Head
	if req.Base != "" {
		diff.Base = req.Base
	}
	return diff, nil
}

func (s *fakeStore) Rebuild(context.Context, history.RepoID) error { return s.err }

func (s *fakeStore) Prune(context.Context, history.RepoID, history.Retention) (int, error) {
	return 0, s.err
}

func (s *fakeStore) Forget(context.Context, history.RepoID) error { return s.err }

func (s *fakeStore) Close() error { return nil }

var _ history.Store = (*fakeStore)(nil)

func testStore() *fakeStore {
	at := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)

	return &fakeStore{
		repos: []history.Repo{
			{
				ID: repoA, Name: "vulnerable-app", Path: "/src/vulnerable-app",
				LastRunAt: at, LastRun: run2, Runs: 2,
				Open: history.Counts{
					Total:      3,
					BySeverity: map[scan.Severity]int{scan.SeverityCritical: 1, scan.SeverityHigh: 2},
				},
			},
			{ID: repoB, Name: "pindrop", Path: "/src/pindrop", LastRun: run1, Runs: 1},
		},
		runs: map[history.RepoID][]history.Run{
			repoA: {
				{
					ID: run2, RepoID: repoA, PrevRun: run1, FinishedAt: at,
					VCS:    history.RunVCS{Branch: "main", Commit: "abcdef1234"},
					Counts: history.Counts{Total: 3, BySeverity: map[scan.Severity]int{scan.SeverityCritical: 1}},
					Delta:  history.DeltaCounts{New: 1, StillOpen: 2, Fixed: 1},
				},
				{
					ID: run1, RepoID: repoA,
					VCS:    history.RunVCS{Branch: "topic"},
					Counts: history.Counts{Total: 3},
				},
			},
			repoB: {{ID: run1, RepoID: repoB}},
		},
		deltas: map[history.RunID][]scan.Delta{
			run2: {
				{Status: scan.StatusNew, Finding: scan.Finding{
					Fingerprint: "a1", RuleID: "CVE-1", Scanner: "trivy",
					Scanners: []string{"osv", "trivy"}, Aliases: []string{"GHSA-1"},
					Category: scan.CategoryVulnerability, Severity: scan.SeverityCritical,
				}},
				{Status: scan.StatusRegressed, Finding: scan.Finding{
					Fingerprint: "b2", RuleID: "CVE-2", Scanner: "osv",
					Category: scan.CategoryVulnerability, Severity: scan.SeverityHigh,
				}},
			},
		},
		docs: map[history.RunID]report.Document{
			run2: {
				SchemaVersion: report.DocumentSchemaVersion,
				Findings: []scan.Finding{{
					Fingerprint: "a1", RuleID: "CVE-1", Scanner: "trivy",
					Category: scan.CategoryVulnerability, Severity: scan.SeverityCritical,
				}},
			},
		},
		states: []history.FindingState{
			{Fingerprint: "a1", Status: scan.StatusOpen, Severity: scan.SeverityCritical},
			{Fingerprint: "z9", Status: scan.StatusFixed, Severity: scan.SeverityLow},
		},
		diff: history.Diff{Counts: history.DeltaCounts{New: 1, Fixed: 1}},
	}
}

func historyServer(t *testing.T, store history.Store) *httpapi.Server {
	t.Helper()
	return newTestServer(t, httpapi.Config{Store: store})
}

func TestNewAcceptsStoreWithoutSource(t *testing.T) {
	t.Parallel()

	if _, err := httpapi.New(httpapi.Config{Store: testStore()}); err != nil {
		t.Fatalf("New() with only a Store error = %v, want nil", err)
	}
}

// TestHistoryRoutesAbsentWithoutStore is the back-compat guard: `pindrop serve
// --results foo.json` configures no store, and must not grow history routes
// that would answer with empty lists as if the history were simply empty.
func TestHistoryRoutesAbsentWithoutStore(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{
		Assets: testAssets(),
		Source: stubSource{doc: testDocument()},
	})

	for _, target := range []string{
		"/api/v1/repos",
		"/api/v1/repos/" + repoA,
		"/api/v1/repos/" + repoA + "/runs",
		"/api/v1/repos/" + repoA + "/runs/" + run2,
		"/api/v1/repos/" + repoA + "/runs/" + run2 + "/findings",
		"/api/v1/repos/" + repoA + "/runs/" + run2 + "/diff",
		"/api/v1/repos/" + repoA + "/states",
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rec := get(t, srv, target)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
			}
			// It must be JSON, not the SPA shell: a client asking for history
			// has to be able to tell "no history here" from "you have not
			// scanned yet", and an HTML page is only a parse error.
			if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Errorf("Content-Type = %q, want JSON", ct)
			}
			if !strings.Contains(rec.Body.String(), "--results") {
				t.Errorf("body = %s, want it to explain the --results mode", rec.Body.String())
			}
		})
	}

	// The single-report routes must be untouched.
	if rec := get(t, srv, "/api/v1/findings"); rec.Code != http.StatusOK {
		t.Errorf("findings status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestStoreBacksLegacyRoutes covers the compatibility shim: a server configured
// with only a Store must still answer the single-report routes the existing
// dashboard page uses, resolved to the newest run of the newest repository.
func TestStoreBacksLegacyRoutes(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	rec := get(t, srv, "/api/v1/findings")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body.Total != 1 {
		t.Errorf("total = %d, want 1 — the newest run of the newest repo", body.Total)
	}
}

// TestEmptyStoreExplainsItself: a store with no history is the first-run state,
// and must produce an actionable message rather than a bare failure.
func TestEmptyStoreExplainsItself(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, &fakeStore{})

	rec := get(t, srv, "/api/v1/repos")
	if rec.Code != http.StatusOK {
		t.Fatalf("repos status = %d, want %d", rec.Code, http.StatusOK)
	}
	// A null here would be indistinguishable from a decode failure client-side.
	if body := rec.Body.String(); !strings.Contains(body, `"repos":[]`) {
		t.Errorf("body = %s, want an empty repos array", body)
	}

	rec = get(t, srv, "/api/v1/findings")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("findings status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if msg := rec.Body.String(); !strings.Contains(msg, "pindrop scan") {
		t.Errorf("message = %s, want it to name the command to run", msg)
	}
}

func TestRepos(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())
	rec := get(t, srv, "/api/v1/repos")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Repos []history.Repo `json:"repos"`
		Total int            `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body.Total != 2 || len(body.Repos) != 2 {
		t.Fatalf("total = %d, len = %d, want 2 and 2", body.Total, len(body.Repos))
	}
	if body.Repos[0].ID != repoA {
		t.Errorf("repos[0].id = %q, want %q — store order must be preserved", body.Repos[0].ID, repoA)
	}
}

func TestRepoByID(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	rec := get(t, srv, "/api/v1/repos/"+repoA)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var repo history.Repo
	if err := json.Unmarshal(rec.Body.Bytes(), &repo); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if repo.Name != "vulnerable-app" {
		t.Errorf("name = %q, want %q", repo.Name, "vulnerable-app")
	}
}

// TestPathTraversalRejected is the headline security test.
//
// [http.ServeMux] percent-decodes a path segment before PathValue returns it,
// so an encoded traversal arrives at the handler already decoded and would
// otherwise be joined straight onto a directory. Every one of these must be a
// 404 that never reaches the store — which the fake enforces by returning an
// unmistakable status if it is ever consulted with a bad ID.
func TestPathTraversalRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
	}{
		{"encoded traversal", "/api/v1/repos/%2e%2e%2f%2e%2e%2fetc"},
		{"encoded traversal in runs", "/api/v1/repos/%2e%2e/runs"},
		{"absolute path", "/api/v1/repos/%2Fetc%2Fpasswd"},
		{"absolute path in runs", "/api/v1/repos/" + repoA + "/runs/%2Fetc%2Fpasswd"},
		{"encoded traversal as run", "/api/v1/repos/" + repoA + "/runs/%2e%2e%2f%2e%2e"},
		{"traversal in findings", "/api/v1/repos/" + repoA + "/runs/%2e%2e/findings"},
		{"traversal in diff", "/api/v1/repos/" + repoA + "/runs/%2e%2e/diff"},
		{"traversal in states", "/api/v1/repos/%2e%2e/states"},
		{"null byte", "/api/v1/repos/" + repoA + "%00/states"},
		{"wrong shape", "/api/v1/repos/not-a-repo-id"},
		{"uppercase hex", "/api/v1/repos/r_0000000000000000000000000000000A"},
		{"too short", "/api/v1/repos/r_0000"},
		{"run without random suffix", "/api/v1/repos/" + repoA + "/runs/20260101T120000Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := testStore()
			srv := historyServer(t, store)

			rec := get(t, srv, tt.target)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d for %s", rec.Code, http.StatusNotFound, tt.target)
			}

			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if body["error"] == "" {
				t.Error("404 has no error message")
			}
			// The rejected value must never be reflected back.
			if strings.Contains(body["error"], "..") || strings.Contains(body["error"], "/etc") {
				t.Errorf("error = %q, want it not to echo the rejected path", body["error"])
			}
		})
	}
}

// TestLiteralDotSegmentNeverReachesAHandler documents the other half of the
// defence: http.ServeMux cleans a path containing a literal ".." and redirects
// before any handler runs, so such a request can never carry a traversal into
// the store. The encoded forms are the ones that do reach a handler, and
// TestPathTraversalRejected covers those.
func TestLiteralDotSegmentNeverReachesAHandler(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	rec := get(t, srv, "/api/v1/repos/..")
	if rec.Code != http.StatusTemporaryRedirect && rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want a redirect from ServeMux path cleaning", rec.Code)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "..") {
		t.Errorf("Location = %q, want the cleaned path", loc)
	}
}

// TestTraversalQueryParamRejected covers the one identifier that arrives as a
// query parameter rather than a path segment, and so is not covered by the
// segment-shaped defences above.
func TestTraversalQueryParamRejected(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	rec := get(t, srv, "/api/v1/repos/"+repoA+"/runs/"+run2+"/diff?against=../../etc")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestRuns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		query      string
		wantTotal  int
		wantNext   string
		wantBranch string
		wantLimit  int
	}{
		{name: "all", query: "", wantTotal: 2},
		{name: "branch filter", query: "?branch=main", wantTotal: 1, wantBranch: "main"},
		{
			name: "limit yields a cursor", query: "?limit=1",
			wantTotal: 1, wantLimit: 1, wantNext: run2,
		},
		{name: "limit above the total has no cursor", query: "?limit=9", wantTotal: 2, wantLimit: 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := testStore()
			srv := historyServer(t, store)

			rec := get(t, srv, "/api/v1/repos/"+repoA+"/runs"+tt.query)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}

			var body struct {
				Runs       []history.Run `json:"runs"`
				Total      int           `json:"total"`
				NextBefore string        `json:"nextBefore"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if body.Total != tt.wantTotal {
				t.Errorf("total = %d, want %d", body.Total, tt.wantTotal)
			}
			if body.NextBefore != tt.wantNext {
				t.Errorf("nextBefore = %q, want %q", body.NextBefore, tt.wantNext)
			}
			// Filters must reach the store, not be applied after it answers.
			if store.lastRun.Branch != tt.wantBranch {
				t.Errorf("store saw branch %q, want %q", store.lastRun.Branch, tt.wantBranch)
			}
			if store.lastRun.Limit != tt.wantLimit {
				t.Errorf("store saw limit %d, want %d", store.lastRun.Limit, tt.wantLimit)
			}
		})
	}
}

func TestRunsQueryPushdown(t *testing.T) {
	t.Parallel()

	store := testStore()
	srv := historyServer(t, store)

	rec := get(t, srv,
		"/api/v1/repos/"+repoA+"/runs?since=2026-01-01T00:00:00Z&until=2026-02-01T00:00:00Z&before="+run2)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if got := store.lastRun.Since; !got.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("since = %v, want 2026-01-01T00:00:00Z", got)
	}
	if got := store.lastRun.Until; !got.Equal(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("until = %v, want 2026-02-01T00:00:00Z", got)
	}
	if store.lastRun.Before != run2 {
		t.Errorf("before = %q, want %q", store.lastRun.Before, run2)
	}
}

func TestRunsBadQuery(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	for _, target := range []string{
		"/api/v1/repos/" + repoA + "/runs?limit=-1",
		"/api/v1/repos/" + repoA + "/runs?limit=lots",
		"/api/v1/repos/" + repoA + "/runs?since=yesterday",
		"/api/v1/repos/" + repoA + "/states?offset=-4",
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rec := get(t, srv, target)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestRunDetail(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	rec := get(t, srv, "/api/v1/repos/"+repoA+"/runs/"+run2)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Run     history.Run `json:"run"`
		Summary struct {
			Total      int            `json:"total"`
			BySeverity map[string]int `json:"bySeverity"`
			ByCategory map[string]int `json:"byCategory"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body.Run.ID != run2 {
		t.Errorf("run.id = %q, want %q", body.Run.ID, run2)
	}
	if body.Summary.Total != 3 {
		t.Errorf("summary.total = %d, want 3", body.Summary.Total)
	}
	if body.Summary.BySeverity["critical"] != 1 {
		t.Errorf("summary.bySeverity[critical] = %d, want 1", body.Summary.BySeverity["critical"])
	}
	// An absent breakdown must be {} rather than null, so the client needs no
	// null check to render a zero.
	if body.Summary.ByCategory == nil {
		t.Error("summary.byCategory = null, want an empty object")
	}
}

func TestRunNotFound(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	for _, target := range []string{
		"/api/v1/repos/r_ffffffffffffffffffffffffffffffff",
		"/api/v1/repos/" + repoA + "/runs/20991231T235959Z-ffffffff",
		"/api/v1/repos/" + repoA + "/runs/20991231T235959Z-ffffffff/findings",
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rec := get(t, srv, target)
			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
			}
		})
	}
}

// TestStoreFailureIs503 separates "you asked for something that isn't there"
// from "the history is temporarily unreadable".
func TestStoreFailureIs503(t *testing.T) {
	t.Parallel()

	store := testStore()
	store.err = errUnreadable
	srv := historyServer(t, store)

	for _, target := range []string{
		"/api/v1/repos",
		"/api/v1/repos/" + repoA,
		"/api/v1/repos/" + repoA + "/runs",
		"/api/v1/repos/" + repoA + "/states",
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rec := get(t, srv, target)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

var errUnreadable = fmt.Errorf("scan history is unreadable")

// TestRunFindingsCarryStatus is what the run-detail page needs: the status must
// be a flat field on each finding, and the finding's own fields must survive
// the embedding unflattened.
func TestRunFindingsCarryStatus(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	rec := get(t, srv, "/api/v1/repos/"+repoA+"/runs/"+run2+"/findings")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Findings []struct {
			Fingerprint string   `json:"fingerprint"`
			Status      string   `json:"status"`
			Severity    string   `json:"severity"`
			Scanners    []string `json:"scanners"`
			Aliases     []string `json:"aliases"`
		} `json:"findings"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body.Total != 2 {
		t.Fatalf("total = %d, want 2", body.Total)
	}

	first := body.Findings[0]
	if first.Status != "new" {
		t.Errorf("findings[0].status = %q, want %q", first.Status, "new")
	}
	if first.Severity != "critical" {
		t.Errorf("findings[0].severity = %q — embedding did not flatten", first.Severity)
	}
	if len(first.Scanners) != 2 || len(first.Aliases) != 1 {
		t.Errorf("findings[0] lost scanners/aliases: %v %v", first.Scanners, first.Aliases)
	}
	if body.Findings[1].Status != "regressed" {
		t.Errorf("findings[1].status = %q, want %q", body.Findings[1].Status, "regressed")
	}
}

// TestFindingQueryPushdown asserts the filters reach the store. Filtering in
// the handler instead would pass every response assertion here and quietly make
// a SQL backend unable to push them into a WHERE clause.
func TestFindingQueryPushdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		query  string
		want   history.FindingQuery
		status int
	}{
		{
			name:  "run findings",
			path:  "/api/v1/repos/" + repoA + "/runs/" + run2 + "/findings",
			query: "?severity=CRITICAL,high&category=vulnerability&status=new&limit=10&offset=5",
			want: history.FindingQuery{
				Severity: []scan.Severity{scan.SeverityCritical, scan.SeverityHigh},
				Category: []scan.Category{scan.CategoryVulnerability},
				Status:   []scan.Status{scan.StatusNew},
				Limit:    10, Offset: 5,
			},
		},
		{
			name:  "states",
			path:  "/api/v1/repos/" + repoA + "/states",
			query: "?status=fixed&severity=low",
			want: history.FindingQuery{
				Severity: []scan.Severity{scan.SeverityLow},
				Status:   []scan.Status{scan.StatusFixed},
			},
		},
		{
			name:  "blank values are dropped",
			path:  "/api/v1/repos/" + repoA + "/states",
			query: "?severity=,,%20,",
			want:  history.FindingQuery{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := testStore()
			srv := historyServer(t, store)

			rec := get(t, srv, tt.path+tt.query)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if !slices.Equal(store.lastFind.Severity, tt.want.Severity) {
				t.Errorf("severity = %v, want %v", store.lastFind.Severity, tt.want.Severity)
			}
			if !slices.Equal(store.lastFind.Category, tt.want.Category) {
				t.Errorf("category = %v, want %v", store.lastFind.Category, tt.want.Category)
			}
			if !slices.Equal(store.lastFind.Status, tt.want.Status) {
				t.Errorf("status = %v, want %v", store.lastFind.Status, tt.want.Status)
			}
			if store.lastFind.Limit != tt.want.Limit || store.lastFind.Offset != tt.want.Offset {
				t.Errorf("limit/offset = %d/%d, want %d/%d",
					store.lastFind.Limit, store.lastFind.Offset, tt.want.Limit, tt.want.Offset)
			}
		})
	}
}

func TestStates(t *testing.T) {
	t.Parallel()

	srv := historyServer(t, testStore())

	rec := get(t, srv, "/api/v1/repos/"+repoA+"/states")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		States []history.FindingState `json:"states"`
		Total  int                    `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body.Total != 2 {
		t.Errorf("total = %d, want 2", body.Total)
	}
	if body.States[1].Status != scan.StatusFixed {
		t.Errorf("states[1].status = %q, want %q — fixed findings must be listed",
			body.States[1].Status, scan.StatusFixed)
	}
}

func TestDiff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		query    string
		wantBase history.RunID
	}{
		{"implicit base", "", ""},
		{"explicit base", "?against=" + run1, run1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := historyServer(t, testStore())

			rec := get(t, srv, "/api/v1/repos/"+repoA+"/runs/"+run2+"/diff"+tt.query)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}

			var diff history.Diff
			if err := json.Unmarshal(rec.Body.Bytes(), &diff); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if diff.Head != run2 {
				t.Errorf("head = %q, want %q", diff.Head, run2)
			}
			if diff.Base != tt.wantBase {
				t.Errorf("base = %q, want %q", diff.Base, tt.wantBase)
			}
			if diff.Counts.New != 1 || diff.Counts.Fixed != 1 {
				t.Errorf("counts = %+v, want New=1 Fixed=1", diff.Counts)
			}
		})
	}
}

// TestRepoSource covers `pindrop serve --repo`: the single-report routes must
// follow the named repository rather than the most recently scanned one.
func TestRepoSource(t *testing.T) {
	t.Parallel()

	store := testStore()
	store.docs[run1] = report.Document{
		Findings: []scan.Finding{
			{Fingerprint: "x", Severity: scan.SeverityLow, Category: scan.CategoryCode},
			{Fingerprint: "y", Severity: scan.SeverityLow, Category: scan.CategoryCode},
		},
	}

	srv := newTestServer(t, httpapi.Config{
		Store:  store,
		Source: httpapi.RepoSource(store, repoB),
	})

	rec := get(t, srv, "/api/v1/summary")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body.Total != 2 {
		t.Errorf("total = %d, want 2 — the named repo's newest run, not the newest repo's", body.Total)
	}
}
