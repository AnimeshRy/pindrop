package cli

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/cliauth"
	"github.com/AnimeshRy/pindrop/internal/tui"
)

func newLogoutCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove saved cloud login credentials",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			opts := tui.CLIAuthOptions(isTerminal(os.Stderr), os.Getenv("TERM"), g.logLevel, g.colorFor(os.Stderr))
			styles := tui.AuthStyles(g.colorFor(os.Stderr))

			creds, err := cliauth.Load()
			if errors.Is(err, cliauth.ErrNotLoggedIn) {
				tui.PrintLine(opts, tui.AuthStatusLine(styles, false, "", ""))
				return nil
			}
			if err != nil {
				return err
			}

			email := creds.DisplayEmail()
			if err := cliauth.Clear(); err != nil {
				return err
			}

			tui.PrintLine(opts, tui.LoggedOutLine(styles, email))
			return nil
		},
	}
}
