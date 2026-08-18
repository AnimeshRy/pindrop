// Command server runs the Pindrop product API.
//
// Auth is delegated to Supabase: this process only verifies JWTs issued by
// Supabase Auth. OAuth login happens entirely in the browser via the app/.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AnimeshRy/pindrop/server/internal/api"
	"github.com/AnimeshRy/pindrop/server/internal/authmw"
	"github.com/AnimeshRy/pindrop/server/internal/config"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	auth, err := authmw.New(authmw.Config{ProjectURL: cfg.SupabaseProjectURL})
	if err != nil {
		return err
	}

	srv := api.New(api.Config{Auth: auth})
	handler := srv.Handler(cfg.CORSOrigin)

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("listening", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}
