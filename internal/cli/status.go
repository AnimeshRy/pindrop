package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// statusOptions holds the flags for `pindrop status`.
type statusOptions struct {
	minSeverity string
	limit       int
}

// newStatusCommand builds `pindrop status`.
func newStatusCommand(_ *globals) *cobra.Command {
	opts := &statusOptions{limit: 10}

	cmd := &cobra.Command{
		Use:   "status [path]",
		Short: "Show what is currently open for a scanned repository",
		Long: "Summarize the findings still open for a repository, from the last\n" +
			"recorded scan. It reads stored history and does not scan anything, so\n" +
			"it returns immediately.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runStatus(cmd.Context(), opts, path)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.minSeverity, "min-severity", "",
		"only count findings at or above this severity")
	f.IntVar(&opts.limit, "limit", 10, "how many open findings to list (0 for all)")

	cmd.RegisterFlagCompletionFunc("min-severity", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"info", "low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

func runStatus(ctx context.Context, opts *statusOptions, path string) error {
	minSeverity, err := parseOptionalSeverity(opts.minSeverity, "--min-severity")
	if err != nil {
		return err
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving %q: %w", path, err)
	}

	store, err := openHistory()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	repo, err := store.RepoByPath(ctx, abs)
	if err != nil {
		if errors.Is(err, history.ErrNotFound) {
			return fmt.Errorf("no scans recorded for %s — run: pindrop scan %s", abs, path)
		}
		return err
	}

	states, err := store.States(ctx, repo.ID, history.FindingQuery{
		Status: openStatuses(),
	})
	if err != nil {
		return err
	}
	states = aboveSeverity(states, minSeverity)

	return writeStatus(os.Stdout, repo, states, opts.limit)
}

// openStatuses lists the statuses describing a finding that is present now.
func openStatuses() []scan.Status {
	return []scan.Status{scan.StatusNew, scan.StatusOpen, scan.StatusRegressed}
}

// aboveSeverity keeps states at or above min. An empty min keeps everything.
func aboveSeverity(states []history.FindingState, min scan.Severity) []history.FindingState {
	if min == "" {
		return states
	}

	kept := make([]history.FindingState, 0, len(states))
	for _, s := range states {
		if s.Severity.Rank() >= min.Rank() {
			kept = append(kept, s)
		}
	}
	return kept
}

// writeStatus renders the summary.
func writeStatus(w io.Writer, repo history.Repo, states []history.FindingState, limit int) error {
	_, _ = fmt.Fprintf(w, "%s  %s\n", repo.Name, repo.Path)
	_, _ = fmt.Fprintf(w, "last scanned %s  ·  %d run(s) recorded\n\n",
		humanizeSince(repo.LastRunAt), repo.Runs)

	if len(states) == 0 {
		_, _ = fmt.Fprintln(w, "Nothing open. ✔")
		return nil
	}

	_, _ = fmt.Fprintf(w, "%d open:", len(states))
	for _, sev := range []scan.Severity{
		scan.SeverityCritical, scan.SeverityHigh, scan.SeverityMedium,
		scan.SeverityLow, scan.SeverityInfo, scan.SeverityUnknown,
	} {
		if n := countSeverity(states, sev); n > 0 {
			_, _ = fmt.Fprintf(w, "  %d %s", n, sev)
		}
	}
	_, _ = fmt.Fprint(w, "\n\n")

	shown := states
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SEVERITY\tSTATUS\tFIRST SEEN\tSUMMARY")
	for _, s := range shown {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			s.Severity, s.Status, humanizeSince(s.FirstSeenAt), s.Title)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("writing status: %w", err)
	}

	if len(shown) < len(states) {
		_, _ = fmt.Fprintf(w, "\n  ... and %d more (use --limit 0 to show all)\n", len(states)-len(shown))
	}
	return nil
}

// countSeverity tallies states at exactly sev.
func countSeverity(states []history.FindingState, sev scan.Severity) int {
	var n int
	for _, s := range states {
		if s.Severity == sev {
			n++
		}
	}
	return n
}

// humanizeSince renders a timestamp as an approximate age, which is what a user
// reading a status line actually wants to know.
func humanizeSince(t time.Time) string {
	if t.IsZero() {
		return "never"
	}

	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	default:
		return t.Format("2006-01-02")
	}
}
