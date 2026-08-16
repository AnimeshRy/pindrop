package cli

import (
	"os"

	"github.com/spf13/cobra"
)

// registerFlagCompletion registers shell completion for a flag. Registration only
// fails when the flag name is invalid, which is a programming error at init time.
func registerFlagCompletion(cmd *cobra.Command, name string, fn func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) {
	_ = cmd.RegisterFlagCompletionFunc(name, fn)
}

func newCompletionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script for pindrop.

To load completions:

Bash:
  $ source <(pindrop completion bash)

  # To install permanently (Linux):
  $ pindrop completion bash | sudo tee /etc/bash_completion.d/pindrop > /dev/null

  # To install permanently (macOS with Homebrew):
  $ pindrop completion bash > $(brew --prefix)/etc/bash_completion.d/pindrop

Zsh:
  $ source <(pindrop completion zsh)

  # To install permanently:
  $ pindrop completion zsh > "${fpath[1]}/_pindrop"
  # You may need to restart your shell or run: compinit

Fish:
  $ pindrop completion fish | source

  # To install permanently:
  $ pindrop completion fish > ~/.config/fish/completions/pindrop.fish

PowerShell:
  PS> pindrop completion powershell | Out-String | Invoke-Expression

  # To install permanently, add the output to your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	}
}
