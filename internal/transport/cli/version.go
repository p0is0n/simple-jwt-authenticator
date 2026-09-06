package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"simple-jwt-authenticator/internal/buildinfo"
)

// newVersionCommand builds the `version` command.
func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		Args:  cobra.NoArgs,
		RunE: func(
			command *cobra.Command,
			_ []string,
		) error {
			if _, err := fmt.Fprint(
				command.OutOrStdout(),
				versionString(
					buildinfo.Current(),
				),
			); err != nil {
				return fmt.Errorf(
					"write version information: %w",
					err,
				)
			}

			return nil
		},
	}
}
