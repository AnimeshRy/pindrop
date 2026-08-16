package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/buildinfo"
	"github.com/AnimeshRy/pindrop/internal/selfupdate"
	"github.com/AnimeshRy/pindrop/internal/tui"
)

func newUpdateCommand() *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update pindrop to the latest version",
		Long: `Check for a newer version of pindrop on GitHub and update the binary in-place.

Queries the latest release from github.com/AnimeshRy/pindrop, compares it to
the running version, downloads the matching binary for this platform, and
atomically replaces the current executable.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			current := buildinfo.Version()

			if current == "dev" {
				return fmt.Errorf("cannot self-update a development build\n" +
					"  Install a released version first, or build from source")
			}

			fmt.Fprintf(os.Stderr, "pindrop %s (%s/%s)\n", current, runtime.GOOS, runtime.GOARCH)
			fmt.Fprintf(os.Stderr, "Checking for updates...\n")

			result, err := selfupdate.Check(ctx, current)
			if err != nil {
				return fmt.Errorf("update check failed: %w", err)
			}

			if !result.Available {
				fmt.Fprintf(os.Stderr, "Already up to date.\n")
				return nil
			}

			fmt.Fprintf(os.Stderr, "New version available: %s → %s\n", result.Current, result.Latest)

			if result.Asset == nil {
				fmt.Fprintf(os.Stderr, "No pre-built binary for %s/%s.\n", runtime.GOOS, runtime.GOARCH)
				fmt.Fprintf(os.Stderr, "Download manually: %s\n", result.Release.HTMLURL)
				return fmt.Errorf("no binary available for this platform")
			}

			if !yes {
				if !isTerminal(os.Stdin) {
					return fmt.Errorf("stdin is not a terminal\n  Re-run with --yes to update without confirmation")
				}
				confirmed, err := tui.Confirm(fmt.Sprintf("Update to v%s?", result.Latest))
				if err != nil {
					return err
				}
				if !confirmed {
					fmt.Fprintln(os.Stderr, "Update cancelled.")
					return nil
				}
			}

			fmt.Fprintf(os.Stderr, "Downloading %s...\n", result.Asset.Name)
			if err := selfupdate.Apply(ctx, result.Asset); err != nil {
				return fmt.Errorf("update failed: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Updated to v%s\n", result.Latest)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation prompt")
	return cmd
}
