package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newConfigCommand builds the `config` parent command with the `validate`
// subcommand.
func newConfigCommand(
	validate ConfigValidate,
) *cobra.Command {
	configCommand := &cobra.Command{
		Use:   "config",
		Short: "Configuration commands",
	}

	configCommand.AddCommand(
		newConfigValidateCommand(
			validate,
		),
	)

	return configCommand
}

// newConfigValidateCommand builds the `config validate` command.
//
// This package owns only the CLI boundary: arguments, flags and conversion
// into CLI-owned command contracts. Concrete configuration loading and
// validation are supplied by the composition root through ConfigValidate.
func newConfigValidateCommand(
	validate ConfigValidate,
) *cobra.Command {
	command := &cobra.Command{
		Use:   "validate [config-path]",
		Short: "Validate a configuration file",
		Args:  cobra.ExactArgs(1),
	}

	modeRaw := command.Flags().String(
		"mode",
		string(ConfigValidationModeServer),
		"validation mode: server, token-generate, token-validate",
	)

	command.RunE = func(
		_ *cobra.Command,
		args []string,
	) error {
		mode, err := parseConfigValidationMode(
			*modeRaw,
		)
		if err != nil {
			return err
		}

		return validate.Validate(
			args[0],
			mode,
		)
	}

	return command
}

// parseConfigValidationMode converts the raw CLI flag value into a supported
// validation mode.
//
// The conversion is intentionally strict. Values are not trimmed or
// case-normalized because silently correcting malformed operator input would
// weaken the CLI contract and make configuration automation less predictable.
func parseConfigValidationMode(
	value string,
) (ConfigValidationMode, error) {
	mode := ConfigValidationMode(
		value,
	)

	switch mode {
	case ConfigValidationModeServer,
		ConfigValidationModeTokenGenerate,
		ConfigValidationModeTokenValidate:
		return mode, nil

	default:
		return "", fmt.Errorf(
			"unsupported configuration validation mode %q",
			value,
		)
	}
}
