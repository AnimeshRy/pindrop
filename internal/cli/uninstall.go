package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	sqlitestore "github.com/AnimeshRy/pindrop/internal/history/sqlite"
	"github.com/AnimeshRy/pindrop/internal/toolinstall"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

type uninstallOptions struct {
	yes           bool
	purgeHistory  bool
}

func newUninstallCommand(_ *globals) *cobra.Command {
	opts := &uninstallOptions{}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove scanners and data that Pindrop installed",
		Long: strings.TrimSpace(`
Remove what Pindrop setup installed: scanner binaries it downloaded and its
install record.

Scan history is kept unless you confirm otherwise (or pass --purge-history).
The pindrop binary itself is never removed — delete it manually if you want the
whole tool gone.`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUninstall(cmd.Context(), opts)
		},
	}

	f := cmd.Flags()
	f.BoolVarP(&opts.yes, "yes", "y", false,
		"remove installed scanners without confirmation (does not delete scan history)")
	f.BoolVar(&opts.purgeHistory, "purge-history", false,
		"also delete all recorded scan history")

	return cmd
}

func runUninstall(ctx context.Context, opts *uninstallOptions) error {
	dir, home, err := setupDirs("")
	if err != nil {
		return err
	}

	record := toolinstall.LoadRecord(home)
	toolNames := make([]string, 0, len(record.Tools))
	for name := range record.Tools {
		toolNames = append(toolNames, name)
	}

	repoCount, runCount, err := historyStats(ctx)
	if err != nil {
		return err
	}

	if len(toolNames) == 0 && repoCount == 0 && !toolpath.SettingsExist() {
		printf(os.Stdout, "Nothing from Pindrop setup is present to remove.\n")
		printUninstallBinaryNote(os.Stdout)
		return nil
	}

	if len(toolNames) > 0 {
		if !opts.yes {
			if !isTerminal(os.Stdin) {
				return errors.New(
					"stdin is not a terminal\n  Re-run with --yes to remove without confirmation")
			}
			ok, err := confirmUninstall(os.Stdin, os.Stdout, dir, len(toolNames))
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("cancelled")
			}
		}
		if err := removeInstalledScanners(dir, home, record, toolNames); err != nil {
			return err
		}
	} else {
		_ = os.Remove(toolinstall.RecordPath(home))
	}

	purge := opts.purgeHistory
	if repoCount > 0 && !purge {
		if opts.yes {
			printf(os.Stdout, "\nScan history (%d %s, %d %s) was left in place.\n",
				repoCount, pluralRepo(repoCount), runCount, pluralRun(runCount))
			printf(os.Stdout, "  Delete it with: pindrop uninstall --purge-history\n")
		} else if isTerminal(os.Stdin) && isTerminal(os.Stdout) {
			dbPath, err := toolpath.DBPath()
			if err != nil {
				return err
			}
			printf(os.Stdout, "\nAlso delete recorded scan history (%d %s, %d %s) at %s? [y/N] ",
				repoCount, pluralRepo(repoCount), runCount, pluralRun(runCount), toolpath.Display(dbPath))
			ok, err := readYesNo(os.Stdin)
			if err != nil {
				return err
			}
			purge = ok
			printf(os.Stdout, "\n")
		}
	}

	if purge {
		dbPath, err := toolpath.DBPath()
		if err != nil {
			return err
		}
		if err := removeHistoryDB(dbPath); err != nil {
			return fmt.Errorf("removing scan history: %w", err)
		}
		printf(os.Stdout, "Removed scan history.\n")
	}

	if err := toolpath.ClearSettings(); err != nil {
		return err
	}

	tryRemoveEmptyTree(home)
	printUninstallBinaryNote(os.Stdout)
	return nil
}

func removeInstalledScanners(dir, home string, record *toolinstall.Record, names []string) error {
	var removed int
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", toolpath.Display(path), err)
		}
		record.Forget(name)
		removed++
	}
	if err := os.Remove(toolinstall.RecordPath(home)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing the install record: %w", err)
	}
	printf(os.Stdout, "Removed %d scanner %s from %s.\n",
		removed, plural(removed), toolpath.Display(dir))
	return nil
}

func historyStats(ctx context.Context) (repos, runs int, err error) {
	path, err := toolpath.DBPath()
	if err != nil {
		return 0, 0, err
	}
	store, err := sqlitestore.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("opening scan history: %w", err)
	}
	defer func() { _ = store.Close() }()

	list, err := store.Repos(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range list {
		runs += r.Runs
	}
	return len(list), runs, nil
}

func removeHistoryDB(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func confirmUninstall(in io.Reader, out io.Writer, dir string, count int) (bool, error) {
	printf(out, "Remove %d scanner %s from %s? [y/N] ", count, plural(count), toolpath.Display(dir))
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("reading your answer: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func tryRemoveEmptyTree(home string) {
	binDir := filepath.Join(home, "bin")
	tryRemoveEmptyDir(binDir)
	tryRemoveEmptyDir(home)
}

func tryRemoveEmptyDir(path string) {
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) > 0 {
		return
	}
	_ = os.Remove(path)
}

func printUninstallBinaryNote(w io.Writer) {
	self, err := os.Executable()
	if err != nil {
		return
	}
	printf(w, "\nThe pindrop program at %s was not removed.\n", toolpath.Display(self))
	printf(w, "Delete that file yourself if you no longer need the CLI.\n")
}

func pluralRepo(n int) string {
	if n == 1 {
		return "repository"
	}
	return "repositories"
}

func pluralRun(n int) string {
	if n == 1 {
		return "run"
	}
	return "runs"
}
