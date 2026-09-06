package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token"
	claimparser "simple-jwt-authenticator/internal/token/claim/parser"
)

// tokenValidateCommand holds the parsed flag values and the injected token
// validation behavior.
type tokenValidateCommand struct {
	validate TokenValidate

	config          string
	token           string
	claimExpression string
}

// newTokenValidateCommand builds the `token validate` command.
func newTokenValidateCommand(
	validate TokenValidate,
) *cobra.Command {
	cmd := &tokenValidateCommand{
		validate: validate,
	}

	command := &cobra.Command{
		Use:   "validate",
		Short: "Validate a JWT using public verification material",
		Args:  cobra.NoArgs,
		RunE:  cmd.run,
	}

	command.Flags().StringVar(
		&cmd.config,
		"config",
		"",
		"path to configuration file (required)",
	)
	_ = command.MarkFlagRequired(
		"config",
	)

	command.Flags().StringVar(
		&cmd.token,
		"token",
		"",
		"JWT to validate (required)",
	)
	_ = command.MarkFlagRequired(
		"token",
	)

	command.Flags().StringVar(
		&cmd.claimExpression,
		"claim-expression",
		"",
		"additional claim policy expression",
	)

	return command
}

// run executes token validation and prints the resulting identity.
//
// The token is forwarded only as credential material and must never be
// included in errors produced by this command.
//
// Claim expressions are parsed at the CLI boundary before validation. A
// malformed expression therefore fails before token parsing or authentication
// can begin.
func (c *tokenValidateCommand) run(
	command *cobra.Command,
	_ []string,
) error {
	request := authentication.Request{
		Credential: authentication.Credential{
			Value: token.Value(c.token),
		},
	}

	if c.claimExpression != "" {
		expression, err := claimparser.Parse(
			c.claimExpression,
		)
		if err != nil {
			return fmt.Errorf(
				"parse --claim-expression: %w",
				err,
			)
		}

		request.ClaimExpression = expression
	}

	identity, err := c.validate.Validate(
		command.Context(),
		c.config,
		request,
	)
	if err != nil {
		return fmt.Errorf(
			"validate token: %w",
			err,
		)
	}

	output, err := json.MarshalIndent(
		identity,
		"",
		"  ",
	)
	if err != nil {
		return fmt.Errorf(
			"encode validated identity output: %w",
			err,
		)
	}

	if _, err := fmt.Fprintln(
		command.OutOrStdout(),
		string(output),
	); err != nil {
		return fmt.Errorf(
			"write validated identity: %w",
			err,
		)
	}

	return nil
}
