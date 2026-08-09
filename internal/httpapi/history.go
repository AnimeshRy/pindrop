package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// noHistory is the message shown when the store exists but has never been
// written to. It names the command rather than describing the state, because
// the user is one command away from a working dashboard.
const noHistory = "no scans recorded yet — run `pindrop scan .` in a project to record one"

// latestRunSource adapts a [history.Store] to [FindingSource].
//
// It exists so that the single-report routes — /api/v1/findings and
// /api/v1/summary, and therefore the dashboard page that predates history —
// keep working when the server was started against a store rather than a file.
// "The newest run of the most recently scanned repository" is what a user who
// just ran `pindrop scan` means by "the findings".
//
// [FindingSource] carries no context, so this uses the background one. The
// history routes below all use the request's context; only this compatibility
// shim does not, and it is not worth widening the interface for.
type latestRunSource struct {
	store history.Store
}

// Document implements [FindingSource].
func (s latestRunSource) Document() (report.Document, error) {
	ctx := context.Background()

	repos, err := s.store.Repos(ctx)
	if err != nil {
		return report.Document{}, fmt.Errorf("reading scan history: %w", err)
	}
	if len(repos) == 0 || repos[0].LastRun == "" {
		return report.Document{}, errors.New(noHistory)
	}

	doc, err := s.store.Document(ctx, repos[0].ID, repos[0].LastRun)
	if err != nil {
		return report.Document{}, fmt.Errorf("reading the newest run of %s: %w", repos[0].Name, err)
	}
	return doc, nil
}

// RepoSource returns a [FindingSource] serving the newest run of one
// repository, for `pindrop serve --repo`. Without it the single-report routes
// would follow whichever repository was scanned most recently, which is the
// wrong answer for a server the user deliberately pointed at one project.
func RepoSource(store history.Store, id history.RepoID) FindingSource {
	return repoSource{store: store, id: id}
}

type repoSource struct {
	store history.Store
	id    history.RepoID
}

// Document implements [FindingSource]; see [latestRunSource] on the context.
func (s repoSource) Document() (report.Document, error) {
	ctx := context.Background()

	repo, err := s.store.RepoByID(ctx, s.id)
	if err != nil {
		return report.Document{}, fmt.Errorf("reading scan history: %w", err)
	}
	if repo.LastRun == "" {
		return report.Document{}, errors.New(noHistory)
	}

	doc, err := s.store.Document(ctx, repo.ID, repo.LastRun)
	if err != nil {
		return report.Document{}, fmt.Errorf("reading the newest run of %s: %w", repo.Name, err)
	}
	return doc, nil
}

// findingView pairs a finding with its lifecycle status for one run.
//
// Status is a view concern, not identity: it depends on which run you are
// looking at, so it must never become a field on [scan.Finding], which is
// hashed into a fingerprint and written to the persisted report. Embedding
// flattens the finding's fields into the same JSON object, so a client sees one
// flat record rather than a wrapper.
type findingView struct {
	scan.Finding
	Status scan.Status `json:"status"`
}

// errNoStore explains a server that was pointed at a single report file. It is
// a 404 rather than an empty history, because the dashboard has to be able to
// tell "this server has no history" from "you have not scanned anything yet"
// and show a different thing for each.
var errNoStore = errors.New(
	"this server was started with --results and serves a single report; " +
		"restart it as `pindrop serve` to browse recorded scans")

// historyRoutes registers the scan-history API.
//
// The routes exist even without a store so that they answer in JSON. Leaving
// them unregistered would hand the request to the SPA catch-all, and a client
// asking for JSON would get an HTML page and a parse error instead of an
// explanation.
func (s *Server) historyRoutes(store history.Store) {
	if store == nil {
		for _, pattern := range []string{
			"GET /api/v1/repos",
			"GET /api/v1/repos/{repoID}",
			"GET /api/v1/repos/{repoID}/runs",
			"GET /api/v1/repos/{repoID}/runs/{runID}",
			"GET /api/v1/repos/{repoID}/runs/{runID}/findings",
			"GET /api/v1/repos/{repoID}/runs/{runID}/diff",
			"GET /api/v1/repos/{repoID}/states",
		} {
			s.mux.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) {
				writeError(w, http.StatusNotFound, errNoStore)
			})
		}
		return
	}

	s.mux.HandleFunc("GET /api/v1/repos", handleRepos(store))
	s.mux.HandleFunc("GET /api/v1/repos/{repoID}", handleRepo(store))
	s.mux.HandleFunc("GET /api/v1/repos/{repoID}/runs", handleRuns(store))
	s.mux.HandleFunc("GET /api/v1/repos/{repoID}/runs/{runID}", handleRun(store))
	s.mux.HandleFunc("GET /api/v1/repos/{repoID}/runs/{runID}/findings", handleRunFindings(store))
	s.mux.HandleFunc("GET /api/v1/repos/{repoID}/runs/{runID}/diff", handleRunDiff(store))
	s.mux.HandleFunc("GET /api/v1/repos/{repoID}/states", handleStates(store))
}

func handleRepos(store history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repos, err := store.Repos(r.Context())
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if repos == nil {
			// An empty history is a legitimate answer, and a JSON null here
			// would make the dashboard's "no scans yet" state indistinguishable
			// from a decode failure.
			repos = []history.Repo{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"repos": repos, "total": len(repos)})
	}
}

func handleRepo(store history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoID, ok := pathRepoID(w, r)
		if !ok {
			return
		}

		repo, err := store.RepoByID(r.Context(), repoID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, repo)
	}
}

func handleRuns(store history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoID, ok := pathRepoID(w, r)
		if !ok {
			return
		}

		q, err := parseRunQuery(r.URL.Query())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		runs, err := store.Runs(r.Context(), repoID, q)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if runs == nil {
			runs = []history.Run{}
		}

		// Paging is anchored on a run ID rather than an offset so a scan
		// finishing between two pages cannot shift the window. A full page
		// always offers a cursor, even when it happens to be the last one — the
		// alternative is asking the store for one extra run on every request.
		nextBefore := ""
		if q.Limit > 0 && len(runs) == q.Limit {
			nextBefore = runs[len(runs)-1].ID.String()
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"runs":       runs,
			"total":      len(runs),
			"nextBefore": nextBefore,
		})
	}
}

func handleRun(store history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoID, runID, ok := pathRunID(w, r)
		if !ok {
			return
		}

		run, err := store.RunByID(r.Context(), repoID, runID)
		if err != nil {
			writeStoreError(w, err)
			return
		}

		// The counts are already on the run, so this needs no run document —
		// which matters because a run whose file is unreadable still has usable
		// metadata, and a summary that 503s on it would hide the whole row.
		writeJSON(w, http.StatusOK, map[string]any{
			"run": run,
			"summary": map[string]any{
				"total":      run.Counts.Total,
				"bySeverity": nonNil(run.Counts.BySeverity),
				"byCategory": nonNil(run.Counts.ByCategory),
			},
		})
	}
}

func handleRunFindings(store history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoID, runID, ok := pathRunID(w, r)
		if !ok {
			return
		}

		q, err := parseFindingQuery(r.URL.Query())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		deltas, err := store.Findings(r.Context(), repoID, runID, q)
		if err != nil {
			writeStoreError(w, err)
			return
		}

		views := make([]findingView, 0, len(deltas))
		for _, d := range deltas {
			views = append(views, findingView{Finding: d.Finding, Status: d.Status})
		}
		writeJSON(w, http.StatusOK, map[string]any{"findings": views, "total": len(views)})
	}
}

func handleRunDiff(store history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoID, runID, ok := pathRunID(w, r)
		if !ok {
			return
		}

		// `against` reaches the store as a run identifier too, so it is
		// validated on the same terms as a path segment.
		against := history.RunID(r.URL.Query().Get("against"))
		if against != "" && !against.Valid() {
			writeError(w, http.StatusNotFound, errors.New("no such run"))
			return
		}

		diff, err := store.DiffRuns(r.Context(), repoID, history.DiffRequest{
			Base: against,
			Head: runID,
		})
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, diff)
	}
}

func handleStates(store history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoID, ok := pathRepoID(w, r)
		if !ok {
			return
		}

		q, err := parseFindingQuery(r.URL.Query())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		states, err := store.States(r.Context(), repoID, q)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if states == nil {
			states = []history.FindingState{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"states": states, "total": len(states)})
	}
}

// pathRepoID extracts and validates the {repoID} path segment, writing a 404
// and reporting false when it is not a well-formed ID.
//
// This is the path-traversal boundary. [http.ServeMux] percent-decodes a
// segment before [http.Request.PathValue] returns it, so a request for
// %2e%2e%2fetc arrives here as "../etc" — and the store joins a repo ID to a
// directory. Validation rejects rather than sanitizes, because cleaning a
// hostile value yields a different valid-looking value, which is the same bug
// wearing a disguise. The store validates again; this is defence in depth, and
// it is also what turns a malformed ID into a 404 rather than a 503.
//
// The response never echoes the rejected value: there is nothing useful in it
// for a legitimate caller, and reflecting attacker-controlled bytes is a habit
// worth not having.
func pathRepoID(w http.ResponseWriter, r *http.Request) (history.RepoID, bool) {
	id := history.RepoID(r.PathValue("repoID"))
	if !id.Valid() {
		writeError(w, http.StatusNotFound, errors.New("no such repository"))
		return "", false
	}
	return id, true
}

// pathRunID validates both path segments; see [pathRepoID].
func pathRunID(w http.ResponseWriter, r *http.Request) (history.RepoID, history.RunID, bool) {
	repoID, ok := pathRepoID(w, r)
	if !ok {
		return "", "", false
	}

	runID := history.RunID(r.PathValue("runID"))
	if !runID.Valid() {
		writeError(w, http.StatusNotFound, errors.New("no such run"))
		return "", "", false
	}
	return repoID, runID, true
}

// writeStoreError maps a store failure onto a status code.
//
// [history.ErrNotFound] is a package sentinel precisely so that "no such run"
// can be told apart from "the store's own file is missing"; everything else is
// a 503, since the API is read-only and any other failure means the history is
// temporarily unreadable rather than the request being wrong.
func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, history.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeError(w, http.StatusServiceUnavailable, err)
}

// parseRunQuery builds a [history.RunQuery] from the query string.
func parseRunQuery(values url.Values) (history.RunQuery, error) {
	q := history.RunQuery{Branch: strings.TrimSpace(values.Get("branch"))}

	var err error
	if q.Since, err = parseTime("since", values.Get("since")); err != nil {
		return history.RunQuery{}, err
	}
	if q.Until, err = parseTime("until", values.Get("until")); err != nil {
		return history.RunQuery{}, err
	}
	if q.Limit, err = parseCount("limit", values.Get("limit")); err != nil {
		return history.RunQuery{}, err
	}

	// An unparseable cursor is a 404 from the store rather than a 400 here, so
	// that a stale bookmark and a deleted run give the same answer.
	q.Before = history.RunID(values.Get("before"))
	return q, nil
}

// parseFindingQuery builds a [history.FindingQuery] from the query string.
//
// Filters are pushed into the store rather than applied to its result. That is
// the whole point of the query type: a SQLite backend turns these into a WHERE
// clause, and a handler that filtered afterwards would quietly make that
// impossible.
func parseFindingQuery(values url.Values) (history.FindingQuery, error) {
	var q history.FindingQuery

	for _, v := range splitValues(values.Get("severity")) {
		q.Severity = append(q.Severity, scan.Severity(v))
	}
	for _, v := range splitValues(values.Get("category")) {
		q.Category = append(q.Category, scan.Category(v))
	}
	for _, v := range splitValues(values.Get("status")) {
		q.Status = append(q.Status, scan.Status(v))
	}

	var err error
	if q.Limit, err = parseCount("limit", values.Get("limit")); err != nil {
		return history.FindingQuery{}, err
	}
	if q.Offset, err = parseCount("offset", values.Get("offset")); err != nil {
		return history.FindingQuery{}, err
	}
	return q, nil
}

// splitValues parses a comma-separated query value into lowercased, non-empty
// values in the order given. It is [splitSet]'s parse for the case where the
// result feeds a slice-shaped filter rather than a membership test.
func splitValues(query string) []string {
	if strings.TrimSpace(query) == "" {
		return nil
	}

	parts := strings.Split(query, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseCount parses a non-negative integer query parameter. An absent value
// means zero, which every store query reads as "no limit".
func parseCount(name, raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a whole number of zero or more, got %q", name, raw)
	}
	return n, nil
}

// parseTime parses an RFC 3339 timestamp query parameter.
func parseTime(name, raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}

	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"%s must be an RFC 3339 timestamp such as 2026-01-31T00:00:00Z, got %q", name, raw)
	}
	return t, nil
}

// nonNil substitutes an empty map for a nil one, so a client never has to tell
// "no findings of any severity" apart from a JSON null.
func nonNil[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return map[K]V{}
	}
	return m
}
