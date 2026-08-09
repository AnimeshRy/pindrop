package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/httpapi"
	"github.com/AnimeshRy/pindrop/web"
)

// defaultResultsPath is where `pindrop scan` is expected to have written its
// report. It is no longer the default for `pindrop serve` — scan history is —
// but it stays the value a bare `--results` implies.
const defaultResultsPath = ".pindrop/report.json"

// shutdownGrace bounds how long in-flight requests get to finish on Ctrl-C.
const shutdownGrace = 5 * time.Second

type serveOptions struct {
	addr string

	// results serves one report file and no history. Empty means unset.
	results string

	// repo scopes the dashboard to the repository a directory belongs to.
	// Empty means unset.
	repo string
}

func newServeCommand(_ *globals) *cobra.Command {
	opts := &serveOptions{}

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the dashboard and JSON API for recorded scans",
		Long: strings.TrimSpace(`
Serve the dashboard and JSON API for recorded scans.

With no flags, every repository in the scan history is browsable: repositories,
their runs over time, and what each run changed.

--repo opens on a single repository. --results serves one JSON report file
instead, with no history; the file is re-read on every request, so re-running a
scan is reflected on the next page refresh without restarting the server.`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.addr, "addr", "127.0.0.1:7777",
		"address to listen on")
	cmd.Flags().StringVar(&opts.results, "results", "",
		"serve a single JSON scan report instead of scan history, e.g. "+defaultResultsPath)
	cmd.Flags().StringVar(&opts.repo, "repo", "",
		"serve the scan history of the repository containing this directory")

	return cmd
}

func runServe(ctx context.Context, opts *serveOptions) error {
	assets, err := web.FS()
	if err != nil {
		if !errors.Is(err, web.ErrNotBuilt) {
			return fmt.Errorf("loading dashboard assets: %w", err)
		}
		// A binary without a UI build still serves a useful API, so this is a
		// warning rather than a fatal error.
		slog.Warn("dashboard assets are not built; serving API only",
			"hint", "run: make web && make build")
		assets = nil
	}

	srv, target, err := newServer(ctx, assets, opts)
	if err != nil {
		return err
	}
	defer target.close()

	httpServer := srv.ListenAndServe(opts.addr)

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "pindrop dashboard: http://%s%s\n", opts.addr, target.path)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("serving: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	// Detach from the cancelled context so shutdown itself is not immediately
	// cancelled by the same Ctrl-C that triggered it.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()

	slog.Info("shutting down")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}
	return nil
}

// serveTarget is what the server was pointed at: the dashboard path worth
// printing, and a release function for whatever had to be opened.
type serveTarget struct {
	// path is appended to the listen address in the startup line. It is empty
	// for the whole-history dashboard and a repository's page for --repo, so
	// that the URL a user clicks lands where they asked to be.
	path string

	// close releases the store, if one was opened. It is never nil.
	close func()
}

// newServer wires the HTTP server to its asset tree and its source of findings.
//
// The three modes are mutually exclusive by construction: --results serves one
// file and registers no history routes at all, --repo serves history scoped to
// one repository, and the default serves the whole history directory.
func newServer(ctx context.Context, assets fs.FS, opts *serveOptions) (*httpapi.Server, serveTarget, error) {
	target := serveTarget{close: func() {}}

	if opts.results != "" && opts.repo != "" {
		return nil, target, errors.New(
			"--results and --repo cannot be combined: --results serves a single " +
				"report file, --repo serves one repository's recorded scan history")
	}

	cfg := httpapi.Config{Assets: assets}

	if opts.results != "" {
		cfg.Source = httpapi.FileSource{Path: opts.results}
	} else {
		store, err := openHistory()
		if err != nil {
			return nil, target, err
		}
		cfg.Store = store
		target.close = func() {
			if err := store.Close(); err != nil {
				slog.Debug("closing scan history", "error", err)
			}
		}

		if opts.repo != "" {
			repo, err := store.RepoByPath(ctx, opts.repo)
			if err != nil {
				target.close()
				return nil, serveTarget{close: func() {}}, fmt.Errorf("serving %s: %w", opts.repo, err)
			}
			cfg.Source = httpapi.RepoSource(store, repo.ID)
			target.path = "/repos/" + repo.ID.String()
		}
	}

	srv, err := httpapi.New(cfg)
	if err != nil {
		target.close()
		return nil, serveTarget{close: func() {}}, fmt.Errorf("creating server: %w", err)
	}
	return srv, target, nil
}
