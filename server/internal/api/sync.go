package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/server/internal/authmw"
	"github.com/AnimeshRy/pindrop/server/internal/orgmw"
	"github.com/AnimeshRy/pindrop/server/internal/syncstore"
)

const maxSyncBody = 32 << 20 // 32 MiB — full run documents can be large.

// SyncHandlers serve CLI ingest and dashboard read routes over syncstore.
type SyncHandlers struct {
	Store syncstore.Store
}

func (h SyncHandlers) register(mux *http.ServeMux, auth *authmw.Middleware, org *orgmw.Middleware) {
	// authmw verifies the JWT; orgmw provisions the personal org. Order matters.
	require := func(next http.Handler) http.Handler {
		return auth.Require(org.Require(next))
	}

	mux.Handle("PUT /api/v1/sync/repos/{clientRepoId}", require(http.HandlerFunc(h.putRepo)))
	mux.Handle("PUT /api/v1/sync/repos/{clientRepoId}/runs/{clientRunId}", require(http.HandlerFunc(h.putRun)))
	mux.Handle("PUT /api/v1/sync/repos/{clientRepoId}/states", require(http.HandlerFunc(h.putStates)))

	mux.Handle("GET /api/v1/repos", require(http.HandlerFunc(h.listRepos)))
	mux.Handle("GET /api/v1/repos/{repoId}", require(http.HandlerFunc(h.getRepo)))
	mux.Handle("GET /api/v1/repos/{repoId}/runs", require(http.HandlerFunc(h.listRuns)))
	mux.Handle("GET /api/v1/repos/{repoId}/runs/{runId}", require(http.HandlerFunc(h.getRun)))
	mux.Handle("GET /api/v1/repos/{repoId}/runs/{runId}/findings", require(http.HandlerFunc(h.getRunFindings)))
	mux.Handle("GET /api/v1/repos/{repoId}/states", require(http.HandlerFunc(h.listStates)))
}

type syncRepoBody struct {
	Name         string          `json:"name"`
	Origin       string          `json:"origin"`
	Path         string          `json:"path"`
	FormerPaths  []string        `json:"formerPaths"`
	Metadata     json.RawMessage `json:"metadata"`
	LastRunID    string          `json:"lastRunId"`
}

func (h SyncHandlers) putRepo(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	clientRepoID := r.PathValue("clientRepoId")
	if clientRepoID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing client repo id"})
		return
	}

	body, err := readJSONLimit[syncRepoBody](w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	repo, link, err := h.Store.LinkRepo(r.Context(), org.ID, syncstore.LinkRepoInput{
		Source:      syncstore.SourceCLI,
		ExternalID:  clientRepoID,
		Name:        body.Name,
		Origin:      body.Origin,
		Path:        body.Path,
		FormerPaths: body.FormerPaths,
		Metadata:    body.Metadata,
		LastRunID:   body.LastRunID,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"repo": repo,
		"link": link,
	})
}

type syncRunBody struct {
	PrevRunID   string                 `json:"prevRunId"`
	StartedAt   time.Time              `json:"startedAt"`
	FinishedAt  time.Time              `json:"finishedAt"`
	DurationMS  int64                  `json:"durationMs"`
	ToolName    string                 `json:"toolName"`
	ToolVersion string                 `json:"toolVersion"`
	VCS         syncstore.RunVCS       `json:"vcs"`
	Scanners    []syncstore.ScanSummary `json:"scanners"`
	ScopeHash   string                 `json:"scopeHash"`
	Counts      syncstore.Counts       `json:"counts"`
	Delta       syncstore.DeltaCounts  `json:"delta"`
	Unreadable  bool                   `json:"unreadable"`
	Problem     string                 `json:"problem"`
	Document    json.RawMessage        `json:"document"`
	Findings    []syncstore.Finding    `json:"findings"`
}

func (h SyncHandlers) putRun(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	clientRepoID := r.PathValue("clientRepoId")
	clientRunID := r.PathValue("clientRunId")
	if clientRepoID == "" || clientRunID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing path parameters"})
		return
	}

	repo, _, err := h.Store.ResolveRepoLink(r.Context(), org.ID, syncstore.SourceCLI, clientRepoID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	body, err := readJSONLimit[syncRunBody](w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	run, err := h.Store.PutRun(r.Context(), org.ID, repo.ID, syncstore.PutRunInput{
		Source:      syncstore.SourceCLI,
		ClientRunID: clientRunID,
		PrevRunID:   body.PrevRunID,
		StartedAt:   body.StartedAt,
		FinishedAt:  body.FinishedAt,
		DurationMS:  body.DurationMS,
		ToolName:    body.ToolName,
		ToolVersion: body.ToolVersion,
		VCS:         body.VCS,
		Scanners:    body.Scanners,
		ScopeHash:   body.ScopeHash,
		Counts:      body.Counts,
		Delta:       body.Delta,
		Unreadable:  body.Unreadable,
		Problem:     body.Problem,
		Document:    body.Document,
		Findings:    body.Findings,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, run)
}

func (h SyncHandlers) putStates(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	clientRepoID := r.PathValue("clientRepoId")
	if clientRepoID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing client repo id"})
		return
	}

	repo, _, err := h.Store.ResolveRepoLink(r.Context(), org.ID, syncstore.SourceCLI, clientRepoID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	states, err := readJSONLimit[[]syncstore.FindingState](w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if states == nil {
		states = []syncstore.FindingState{}
	}

	if err := h.Store.PutStates(r.Context(), org.ID, repo.ID, states); err != nil {
		writeStoreError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h SyncHandlers) listRepos(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	var source syncstore.Source
	if s := strings.TrimSpace(r.URL.Query().Get("source")); s != "" {
		source = syncstore.Source(s)
		if !source.Valid() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid source filter"})
			return
		}
	}

	repos, err := h.Store.ListRepos(r.Context(), org.ID, source)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if repos == nil {
		repos = []syncstore.Repo{}
	}
	writeJSON(w, http.StatusOK, repos)
}

func (h SyncHandlers) getRepo(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	repoID := r.PathValue("repoId")
	repo, err := h.Store.GetRepo(r.Context(), org.ID, repoID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, repo)
}

func (h SyncHandlers) listRuns(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	repoID := r.PathValue("repoId")
	runs, err := h.Store.ListRuns(r.Context(), org.ID, repoID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if runs == nil {
		runs = []syncstore.Run{}
	}
	writeJSON(w, http.StatusOK, runs)
}

func (h SyncHandlers) getRun(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	repoID := r.PathValue("repoId")
	runID := r.PathValue("runId")
	run, err := h.Store.GetRun(r.Context(), org.ID, repoID, runID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (h SyncHandlers) getRunFindings(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	runID := r.PathValue("runId")
	q := syncstore.FindingQuery{
		RunID:    runID,
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Category: strings.TrimSpace(r.URL.Query().Get("category")),
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Search:   strings.TrimSpace(r.URL.Query().Get("q")),
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid limit"})
			return
		}
		q.Limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid offset"})
			return
		}
		q.Offset = n
	}

	findings, total, err := h.Store.ListRunFindings(r.Context(), org.ID, q)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if findings == nil {
		findings = []syncstore.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": findings,
		"total":    total,
	})
}

func (h SyncHandlers) listStates(w http.ResponseWriter, r *http.Request) {
	org, ok := orgmw.OrgFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	repoID := r.PathValue("repoId")
	states, err := h.Store.ListStates(r.Context(), org.ID, repoID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if states == nil {
		states = []syncstore.FindingState{}
	}
	writeJSON(w, http.StatusOK, states)
}

func readJSONLimit[T any](w http.ResponseWriter, r *http.Request) (T, error) {
	var zero T
	r.Body = http.MaxBytesReader(w, r.Body, maxSyncBody)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&zero); err != nil {
		if errors.Is(err, io.EOF) {
			return zero, errors.New("empty request body")
		}
		return zero, err
	}
	return zero, nil
}

func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, syncstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}
