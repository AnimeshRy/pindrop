package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/cliauth"
	"github.com/AnimeshRy/pindrop/internal/tui"
)

func newLoginCommand(g *globals) *cobra.Command {
	var provider string
	var force bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to sync scan history to the cloud dashboard",
		Long: strings.TrimSpace(`
Opens a browser to sign in with GitHub or Google. Your refresh token is saved
locally at ~/.pindrop/credentials.json so later sync commands can authenticate
without prompting again.`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLogin(cmd, g, provider, force)
		},
	}

	cmd.Flags().StringVar(&provider, "provider", "", "OAuth provider: github or google")
	cmd.Flags().BoolVar(&force, "force", false, "sign in even if already logged in")
	return cmd
}

func runLogin(cmd *cobra.Command, g *globals, flagProvider string, force bool) error {
	ctx := cmd.Context()
	opts := tui.CLIAuthOptions(isTerminal(os.Stderr), os.Getenv("TERM"), g.logLevel, g.colorFor(os.Stderr))
	// WSL skips auto-open; plain lines keep the full OAuth URL out of bubbletea's
	// terminal-width frame (which truncates long query strings).
	if !cliauth.AutoOpenBrowser() {
		opts.Mode = tui.ModePlain
	}
	styles := tui.AuthStyles(g.colorFor(os.Stderr))

	if existing, err := cliauth.Load(); err == nil {
		tui.PrintLine(opts, tui.LoggedInLine(styles, existing))
		if !force {
			if !isTerminal(os.Stdin) {
				return fmt.Errorf("already logged in — re-run with --force to switch accounts")
			}
			ok, confirmErr := tui.Confirm("Sign in with a different account?")
			if confirmErr != nil {
				return confirmErr
			}
			if !ok {
				_, _ = fmt.Fprintln(os.Stderr, "Login cancelled.")
				return nil
			}
		}
	} else if !errors.Is(err, cliauth.ErrNotLoggedIn) {
		return err
	}

	p, err := resolveLoginProvider(flagProvider)
	if err != nil {
		return err
	}

	session := tui.StartLogin(string(p), opts)
	defer session.Stop()

	loginSession, err := cliauth.Login(ctx, p, session.Progress)
	if err != nil {
		return err
	}

	if err := cliauth.Save(loginSession.Credentials); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	tui.PrintLine(opts, tui.LoginSuccessLine(styles, loginSession.Credentials))
	return nil
}

func resolveLoginProvider(flagProvider string) (cliauth.Provider, error) {
	if flagProvider != "" {
		p := cliauth.Provider(strings.ToLower(flagProvider))
		if !p.Valid() {
			return "", fmt.Errorf("invalid --provider %q: want github or google", flagProvider)
		}
		return p, nil
	}

	if !isTerminal(os.Stdin) {
		return "", fmt.Errorf("stdin is not a terminal\n  Pass --provider github or --provider google")
	}

	choice, err := tui.AskOAuthProvider()
	if err != nil {
		return "", err
	}
	if choice.Cancelled {
		_, _ = fmt.Fprintln(os.Stderr, "Login cancelled.")
		return "", fmt.Errorf("login cancelled")
	}

	p := cliauth.Provider(choice.Provider)
	if !p.Valid() {
		return "", fmt.Errorf("unsupported provider %q", choice.Provider)
	}
	return p, nil
}
