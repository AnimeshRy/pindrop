package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/history"
)

// historyOptions holds the flags for `pindrop history`.
type historyOptions struct {
	limit  int
	branch string
	yes    bool
	keep   int
}

// newHistoryCommand builds `pindrop history` and its subcommands.
func newHistoryCommand(_ *globals) *cobra.Command {
	opts := &historyOptions{limit: 20, keep: 50}

	cmd := &cobra.Command{
		Use:   "history [path]",
		Short: "List scanned repositories, or one repository's runs",
		Long: "With no argument, list every repository Pindrop has scanned. With a\n" +
			"path, list that repository's runs, newest first, showing what changed\n" +
			"between each run and the one before it.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return runHistoryRepos(cmd.Context())
			}
			return runHistoryRuns(cmd.Context(), opts, args[0])
		},
	}

	f := cmd.Flags()
	f.IntVar(&opts.limit, "limit", 20, "how many runs to show (0 for all)")
	f.StringVar(&opts.branch, "branch", "", "only show runs from this branch")

	cmd.AddCommand(newHistoryRemoveCommand(opts), newHistoryPruneCommand(opts))
	return cmd
}

// newHistoryRemoveCommand builds `pindrop history rm`.
func newHistoryRemoveCommand(opts *historyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <path>",
		Short: "Delete everything stored about a repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHistoryRemove(cmd.Context(), opts, args[0])
		},
	}
	cmd.Flags().BoolVar(&opts.yes, "yes", false, "do not ask for confirmation")
	return cmd
}

// newHistoryPruneCommand builds `pindrop history prune`.
func newHistoryPruneCommand(opts *historyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prune [path]",
		Short: "Drop old runs, keeping the most recent",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			}
			return runHistoryPrune(cmd.Context(), opts, path)
		},
	}
	cmd.Flags().IntVar(&opts.keep, "keep", 50, "how many runs to keep per repository")
	return cmd
}

func runHistoryRepos(ctx context.Context) error {
	store, err := openHistory()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	repos, err := store.Repos(ctx)
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No scans recorded yet — run: pindrop scan .")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "REPOSITORY\tOPEN\tRUNS\tLAST SCAN\tPATH")
	for _, r := range repos {
		path := r.Path
		if r.Missing {
			path += "  (missing)"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\n",
			r.Name, r.Open.Total, r.Runs, humanizeSince(r.LastRunAt), path)
	}
	return flush(tw)
}

func runHistoryRuns(ctx context.Context, opts *historyOptions, path string) error {
	store, err := openHistory()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	repo, err := resolveRepo(ctx, store, path)
	if err != nil {
		return err
	}

	runs, err := store.Runs(ctx, repo.ID, history.RunQuery{
		Branch: opts.branch,
		Limit:  opts.limit,
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stdout, "%s  %s\n\n", repo.Name, repo.Path)
	if len(runs) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No runs match.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "WHEN\tBRANCH\tCOMMIT\tFINDINGS\tCHANGED")
	for _, r := range runs {
		commit := r.VCS.Commit
		if len(commit) > 7 {
			commit = commit[:7]
		}
		line := changeSummary(r)
		if r.Unreadable {
			line = "unreadable: " + r.Problem
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n",
			humanizeSince(r.StartedAt), orDash(r.VCS.Branch), orDash(commit),
			r.Counts.Total, line)
	}
	return flush(tw)
}

func runHistoryRemove(ctx context.Context, opts *historyOptions, path string) error {
	store, err := openHistory()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	repo, err := resolveRepo(ctx, store, path)
	if err != nil {
		return err
	}

	if !opts.yes {
		_, _ = fmt.Fprintf(os.Stderr,
			"This deletes %d run(s) recorded for %s.\nRe-run with --yes to confirm.\n",
			repo.Runs, repo.Path)
		return nil
	}

	if err := store.Forget(ctx, repo.ID); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "Deleted the history for %s\n", repo.Path)
	return nil
}

func runHistoryPrune(ctx context.Context, opts *historyOptions, path string) error {
	store, err := openHistory()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	repos, err := prunable(ctx, store, path)
	if err != nil {
		return err
	}

	var total int
	for _, r := range repos {
		n, err := store.Prune(ctx, r.ID, history.Retention{MaxRuns: opts.keep})
		if err != nil {
			return err
		}
		total += n
	}

	_, _ = fmt.Fprintf(os.Stdout, "Removed %d run(s) across %d repositor%s\n",
		total, len(repos), repoPlural(len(repos)))
	return nil
}

// prunable returns the repositories a prune applies to: one when a path is
// given, every one otherwise.
func prunable(ctx context.Context, store history.Store, path string) ([]history.Repo, error) {
	if path == "" {
		return store.Repos(ctx)
	}
	repo, err := resolveRepo(ctx, store, path)
	if err != nil {
		return nil, err
	}
	return []history.Repo{repo}, nil
}

// resolveRepo finds the repository for a path, with an actionable error when
// there is none. Our users are not security engineers: "not found" alone is not
// something anyone can act on.
func resolveRepo(ctx context.Context, store history.Store, path string) (history.Repo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return history.Repo{}, fmt.Errorf("resolving %q: %w", path, err)
	}

	repo, err := store.RepoByPath(ctx, abs)
	if err != nil {
		if errors.Is(err, history.ErrNotFound) {
			return history.Repo{}, fmt.Errorf(
				"no scans recorded for %s — run: pindrop scan %s", abs, path)
		}
		return history.Repo{}, err
	}
	return repo, nil
}

// changeSummary describes one run against its predecessor.
//
// "no longer detected" rather than "fixed": a scanner ceasing to report
// something is a weaker claim than a fix, and a security tool that overstates
// its conclusions teaches people to discount them.
func changeSummary(r history.Run) string {
	if r.PrevRun == "" {
		return "first run"
	}

	var parts []string
	if r.Delta.New > 0 {
		parts = append(parts, fmt.Sprintf("+%d new", r.Delta.New))
	}
	if r.Delta.Regressed > 0 {
		parts = append(parts, fmt.Sprintf("%d returned", r.Delta.Regressed))
	}
	if r.Delta.Fixed > 0 {
		parts = append(parts, fmt.Sprintf("-%d no longer detected", r.Delta.Fixed))
	}
	if len(parts) == 0 {
		return "no change"
	}

	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}

// orDash renders an empty string as a dash, so a column never looks truncated.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// flush finalizes a tabwriter, wrapping the error.
func flush(tw *tabwriter.Writer) error {
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// repoPlural returns the suffix for "repositor(y|ies)".
func repoPlural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
