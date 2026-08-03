package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/buildinfo"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
			return err
		},
	}
}
