// Package cli assembles Pindrop's command-line interface.
//
// This package is the composition root: it is the only place that knows which
// concrete scanners exist and wires them to the domain interfaces. Keeping that
// knowledge here is what lets internal/scan stay free of any dependency on its
// own adapters.
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/buildinfo"
)

// globals holds flags shared by every subcommand.
type globals struct {
	logLevel string
	noColor  bool
}

// Execute parses the command line and runs the selected command.
//
// It returns an error rather than exiting so that main owns the single exit
// point and deferred cleanup always runs.
func Execute(ctx context.Context) error {
	var g globals

	root := &cobra.Command{
		Use:   buildinfo.Name,
		Short: "Find, prioritize, and track security issues in your code",
		Long: strings.TrimSpace(`
Pindrop runs security scanners over your code and turns their raw output into a
short, ranked list of things actually worth fixing.

Findings are normalized into one model and given a stable fingerprint, so an
issue keeps its identity across scans even when the surrounding code moves.`),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return g.setupLogging()
		},
	}

	root.PersistentFlags().StringVar(&g.logLevel, "log-level", "info",
		"log verbosity: debug, info, warn, error")
	root.PersistentFlags().BoolVar(&g.noColor, "no-color", false,
		"disable colored output")

	root.AddCommand(
		newSetupCommand(&g),
		newUninstallCommand(&g),
		newScanCommand(&g),
		newServeCommand(&g),
		newStatusCommand(&g),
		newHistoryCommand(&g),
		newVersionCommand(),
		newCompletionCommand(),
		newUpdateCommand(),
	)

	registerFlagCompletion(root, "log-level", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"debug", "info", "warn", "error"}, cobra.ShellCompDirectiveNoFileComp
	})

	return root.ExecuteContext(ctx)
}

// setupLogging installs the process-wide structured logger.
//
// Logs go to stderr so that stdout carries only report output and stays safe to
// pipe into jq or redirect to a file.
func (g *globals) setupLogging() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(g.logLevel)); err != nil {
		return fmt.Errorf("invalid --log-level %q: want debug, info, warn, or error", g.logLevel)
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
	return nil
}

// color reports whether the report on stdout should be colorized.
func (g *globals) color() bool { return g.colorFor(os.Stdout) }

// colorFor reports whether output written to f should be colorized: only when the
// user has not opted out, NO_COLOR is unset, and f is an interactive terminal.
//
// Parameterized by file because the report goes to stdout while progress goes to
// stderr, and the two are redirected independently — `pindrop scan . | less` has
// a non-terminal stdout and a terminal stderr, and should color the second.
func (g *globals) colorFor(f *os.File) bool {
	if g.noColor {
		return false
	}
	// https://no-color.org — any non-empty value disables color.
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTerminal(f)
}

// isTerminal reports whether f is a character device, which is a good enough
// proxy for "a human is watching" without pulling in golang.org/x/term.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
