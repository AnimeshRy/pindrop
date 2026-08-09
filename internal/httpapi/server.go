// Package httpapi serves the Pindrop dashboard and its read-only JSON API.
//
// Phase 0 serves a single scan report from disk. The routes are shaped the way
// the eventual multi-tenant API will be shaped — versioned under /api/v1 — so
// that the frontend does not have to be rewritten when a database arrives.
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/buildinfo"
	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/report"
)

// FindingSource supplies the report the API serves. Phase 0 reads a file on
// each request so that re-running a scan is reflected without a restart; later
// phases will back this with a database.
type FindingSource interface {
	// Document returns the current scan report.
	Document() (report.Document, error)
}

// Config configures a [Server].
type Config struct {
	// Assets is the built dashboard. A nil value serves a placeholder page
	// explaining how to build the frontend, which keeps the API usable in
	// development.
	Assets fs.FS

	// Source supplies the single report served by /api/v1/findings and
	// /api/v1/summary. Required unless Store is set, in which case it defaults
	// to the newest run of the most recently scanned repository.
	Source FindingSource

	// Store supplies scan history. When it is nil — `pindrop serve --results
	// foo.json`, which has one report and no history — the /api/v1/repos routes
	// answer 404 with an explanation rather than an empty list. An empty list
	// would be a lie that reads as lost data, and the dashboard needs to tell
	// the two apart to fall back to its single-report view.
	Store history.Store
}

// Server routes dashboard and API requests.
type Server struct {
	mux *http.ServeMux
}

// New returns a Server wired to cfg.
func New(cfg Config) (*Server, error) {
	if cfg.Source == nil && cfg.Store == nil {
		return nil, errors.New("httpapi: Source or Store is required")
	}
	if cfg.Source == nil {
		cfg.Source = latestRunSource{store: cfg.Store}
	}

	s := &Server{mux: http.NewServeMux()}
	s.routes(cfg)
	return s, nil
}

// ServeHTTP implements [http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// routes registers every handler. Method-qualified patterns require Go 1.22 or
// later, which is why no third-party router is needed.
func (s *Server) routes(cfg Config) {
	s.mux.HandleFunc("GET /api/v1/healthz", handleHealth)
	s.mux.HandleFunc("GET /api/v1/findings", handleFindings(cfg.Source))
	s.mux.HandleFunc("GET /api/v1/summary", handleSummary(cfg.Source))

	s.historyRoutes(cfg.Store)

	// The catch-all must come last in specificity terms; ServeMux resolves by
	// pattern precision rather than registration order, so /api/v1/... still
	// wins over "/".
	s.mux.Handle("GET /", spaHandler(cfg.Assets))
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"tool":    buildinfo.Name,
		"version": buildinfo.Version(),
	})
}

// handleFindings serves the full finding list.
func handleFindings(src FindingSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc, err := src.Document()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}

		findings := doc.Findings
		if severity := r.URL.Query().Get("severity"); severity != "" {
			findings = filterSeverity(findings, severity)
		}
		if category := r.URL.Query().Get("category"); category != "" {
			findings = filterCategory(findings, category)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"findings": findings,
			"total":    len(findings),
		})
	}
}

// handleSummary serves the counts the dashboard header needs, so the frontend
// does not have to download every finding to render a tile.
func handleSummary(src FindingSource) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		doc, err := src.Document()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}

		bySeverity := make(map[string]int)
		byCategory := make(map[string]int)
		for _, f := range doc.Findings {
			bySeverity[string(f.Severity)]++
			byCategory[string(f.Category)]++
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"total":       len(doc.Findings),
			"bySeverity":  bySeverity,
			"byCategory":  byCategory,
			"scans":       doc.Scans,
			"generatedAt": doc.GeneratedAt,
		})
	}
}

// spaHandler serves the built dashboard, falling back to index.html for any
// path the asset tree does not contain.
//
// The fallback is what makes client-side routing work: a browser loading
// /findings directly must receive the app shell, not a 404, and let the router
// resolve the path.
func spaHandler(assets fs.FS) http.Handler {
	if assets == nil {
		return http.HandlerFunc(handleMissingUI)
	}

	fileServer := http.FileServer(http.FS(assets))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")

		// The shell is served through serveIndex on every path that resolves
		// to it — including "/" — so it consistently carries no-cache. Letting
		// the file server handle it would cache the document and leave users
		// on a stale shell that references deleted bundles.
		if name == "" || name == "index.html" {
			serveIndex(w, r, assets)
			return
		}

		if _, err := fs.Stat(assets, name); err != nil {
			serveIndex(w, r, assets)
			return
		}

		// Vite fingerprints bundle filenames, so those are safe to cache
		// forever: a new build produces a new name.
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// serveIndex writes the SPA shell for an unmatched path.
func serveIndex(w http.ResponseWriter, r *http.Request, assets fs.FS) {
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		handleMissingUI(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(index); err != nil {
		slog.Debug("writing index.html", "error", err)
	}
}

// handleMissingUI explains how to build the dashboard, rather than returning a
// bare 404 that looks like a bug.
func handleMissingUI(w http.ResponseWriter, _ *http.Request) {
	const page = `<!doctype html>
<title>Pindrop</title>
<style>
  body { font: 16px/1.6 ui-monospace, monospace; margin: 4rem auto; max-width: 40rem; padding: 0 1rem; }
  code { background: #f4f4f5; padding: .15em .4em; border-radius: 4px; }
  @media (prefers-color-scheme: dark) {
    body { background: #18181b; color: #e4e4e7; }
    code { background: #27272a; }
  }
</style>
<h1>Dashboard not built</h1>
<p>The API is running, but this binary was compiled without the frontend assets.</p>
<p>Build them with:</p>
<p><code>make web &amp;&amp; make build</code></p>
<p>The JSON API is available at <code>/api/v1/findings</code>.</p>
`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, page); err != nil {
		slog.Debug("writing placeholder page", "error", err)
	}
}

// ListenAndServe runs the server until ctx-driven shutdown by the caller.
// Timeouts are set because a public-facing server without them is a trivially
// exhaustible resource.
func (s *Server) ListenAndServe(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		slog.Error("encoding response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
