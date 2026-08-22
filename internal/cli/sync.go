package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/cliauth"
	"github.com/AnimeshRy/pindrop/internal/history"
	"github.com/AnimeshRy/pindrop/internal/syncclient"
	"github.com/AnimeshRy/pindrop/internal/tui"
)

func newSyncCommand(g *globals) *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:   "sync [path]",
		Short: "Push local scan history to the cloud dashboard",
		Long: strings.TrimSpace(`
Uploads repositories, runs, findings, and lifecycle state from ~/.pindrop/pindrop.db
to your Pindrop account. Re-running sync is safe: already-uploaded runs are skipped
using a local checkpoint file.

Run pindrop login first if you have not signed in yet.`),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runSync(cmd.Context(), g, path, all)
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "sync every repository in local history")
	return cmd
}

func runSync(ctx context.Context, g *globals, path string, all bool) error {
	cfg, err := cliauth.LoadConfig()
	if err != nil {
		return err
	}

	creds, err := cliauth.Load()
	if err != nil {
		if errors.Is(err, cliauth.ErrNotLoggedIn) {
			return fmt.Errorf("not logged in — run: pindrop login")
		}
		return err
	}

	opts := tui.CLIAuthOptions(isTerminal(os.Stderr), os.Getenv("TERM"), g.logLevel, g.colorFor(os.Stderr))
	styles := tui.AuthStyles(g.colorFor(os.Stderr))
	tui.PrintLine(opts, tui.SyncAsLine(styles, creds))
	_, _ = fmt.Fprintln(os.Stderr)

	client, err := newSyncClient(ctx, cfg)
	if err != nil {
		return err
	}

	store, err := openHistory()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	repos, err := syncTargets(ctx, store, path, all)
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "No repositories to sync.")
		return nil
	}

	state, err := syncclient.LoadState()
	if err != nil {
		return err
	}

	var failed int
	for _, repo := range repos {
		if err := syncRepo(ctx, store, client, state, repo); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Sync failed for %s: %v\n", repo.Name, err)
			failed++
			continue
		}
	}

	if err := syncclient.SaveState(state); err != nil {
		return fmt.Errorf("saving sync checkpoint: %w", err)
	}

	if failed > 0 {
		return fmt.Errorf("%d repositor%s failed to sync", failed, repoPlural(failed))
	}
	return nil
}

func newSyncClient(ctx context.Context, cfg cliauth.Config) (syncclient.Client, error) {
	token, _, err := cliauth.AccessToken(ctx)
	if err != nil {
		if errors.Is(err, cliauth.ErrNotLoggedIn) {
			return syncclient.Client{}, fmt.Errorf("not logged in — run: pindrop login")
		}
		return syncclient.Client{}, err
	}

	return syncclient.Client{
		BaseURL: cfg.APIBaseURL,
		Token:   token,
		Refresh: func(ctx context.Context) (string, error) {
			creds, loadErr := cliauth.Load()
			if loadErr != nil {
				return "", loadErr
			}
			session, refreshErr := cliauth.Refresh(ctx, creds)
			if refreshErr != nil {
				return "", refreshErr
			}
			if saveErr := cliauth.Save(session.Credentials); saveErr != nil {
				return "", saveErr
			}
			return session.AccessToken, nil
		},
	}, nil
}

func syncTargets(ctx context.Context, store history.Store, path string, all bool) ([]history.Repo, error) {
	if all {
		return store.Repos(ctx)
	}
	repo, err := resolveRepo(ctx, store, path)
	if err != nil {
		return nil, err
	}
	return []history.Repo{repo}, nil
}

func syncRepo(ctx context.Context, store history.Store, client syncclient.Client, state syncclient.State, repo history.Repo) error {
	checkpoint := history.RunID(state.LastSynced[repo.ID])

	_, _ = fmt.Fprintf(os.Stderr, "Syncing %s…\n", repo.Name)

	if err := client.PutRepo(ctx, string(repo.ID), syncclient.RepoRequest(repo)); err != nil {
		return err
	}

	runs, err := store.Runs(ctx, repo.ID, history.RunQuery{})
	if err != nil {
		return err
	}

	toSync := syncclient.RunsToSync(runs, checkpoint)
	for _, run := range toSync {
		doc, err := store.Document(ctx, repo.ID, run.ID)
		if err != nil {
			return fmt.Errorf("run %s: %w", run.ID, err)
		}

		deltas, err := store.Findings(ctx, repo.ID, run.ID, history.FindingQuery{})
		if err != nil {
			return fmt.Errorf("run %s findings: %w", run.ID, err)
		}

		req, err := syncclient.RunRequest(run, doc, deltas)
		if err != nil {
			return err
		}

		if err := client.PutRun(ctx, string(repo.ID), string(run.ID), req); err != nil {
			return fmt.Errorf("run %s: %w", run.ID, err)
		}
	}

	states, err := store.States(ctx, repo.ID, history.FindingQuery{})
	if err != nil {
		return err
	}

	if err := client.PutStates(ctx, string(repo.ID), syncclient.StatesFromHistory(states)); err != nil {
		return err
	}

	if repo.LastRun != "" {
		state.LastSynced[repo.ID] = string(repo.LastRun)
	}

	_, _ = fmt.Fprintf(os.Stderr, "  %d run(s) synced for %s\n", len(toSync), repo.Name)
	return nil
}
