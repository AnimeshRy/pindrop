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
// report. Keeping a convention means `pindrop serve` needs no arguments in the
// common case.
const defaultResultsPath = ".pindrop/report.json"

// shutdownGrace bounds how long in-flight requests get to finish on Ctrl-C.
const shutdownGrace = 5 * time.Second

type serveOptions struct {
	addr           string
	results        string
	mode           string
	supabaseURL    string
	publishableKey string
}

func newServeCommand(_ *globals) *cobra.Command {
	opts := &serveOptions{}

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the dashboard and JSON API for a scan report",
		Long: strings.TrimSpace(`
Serve the dashboard and JSON API for a scan report.

The report is re-read from disk on every request, so re-running a scan is
reflected on the next page refresh without restarting the server.`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.addr, "addr", "127.0.0.1:7777",
		"address to listen on")
	cmd.Flags().StringVar(&opts.results, "results", defaultResultsPath,
		"path to the JSON scan report to serve")
	cmd.Flags().StringVar(&opts.mode, "mode", "",
		"deployment mode: self-hosted (default) or cloud")
	cmd.Flags().StringVar(&opts.supabaseURL, "supabase-url", "",
		"Supabase project URL for cloud mode (overrides PINDROP_SUPABASE_URL)")
	cmd.Flags().StringVar(&opts.publishableKey, "supabase-publishable-key", "",
		"Supabase publishable API key for cloud mode (overrides PINDROP_SUPABASE_PUBLISHABLE_KEY)")

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

	srv, err := newServer(assets, opts)
	if err != nil {
		return err
	}

	httpServer := srv.ListenAndServe(opts.addr)

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "pindrop dashboard: http://%s\n", opts.addr)
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

// newServer wires the HTTP server to its asset tree and report source.
func newServer(assets fs.FS, opts *serveOptions) (*httpapi.Server, error) {
	mode, err := resolveServeMode(opts.mode)
	if err != nil {
		return nil, err
	}

	cfg, err := buildHTTPServerConfig(
		mode,
		resolveSupabaseURL(opts.supabaseURL),
		resolvePublishableKey(opts.publishableKey),
		assets,
		opts.results,
	)
	if err != nil {
		return nil, err
	}

	srv, err := httpapi.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating server: %w", err)
	}
	return srv, nil
}
