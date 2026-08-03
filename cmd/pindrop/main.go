// The pindrop command scans a codebase for security findings and serves them
// as a ranked, deduplicated dashboard.
//
// Usage:
//
//	pindrop scan [path]   scan a directory and report findings
//	pindrop serve         serve the dashboard and JSON API
//	pindrop version       print build information
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AnimeshRy/pindrop/internal/buildinfo"
	"github.com/AnimeshRy/pindrop/internal/cli"
)

func main() {
	if err := run(); err != nil {
		// Cobra already reports usage errors; anything reaching here is a
		// runtime failure worth printing plainly.
		fmt.Fprintf(os.Stderr, "%s: %v\n", buildinfo.Name, err)
		os.Exit(1)
	}
}

// run holds all of the program logic so that main has a single exit point and
// every deferred cleanup gets to run.
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.Execute(ctx); err != nil {
		// A cancelled context means the user pressed Ctrl-C. That is a normal
		// way to end a long scan, not an error to shout about.
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return nil
}
