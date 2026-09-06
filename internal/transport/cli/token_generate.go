package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"simple-jwt-authenticator/internal/token"
)

// tokenGenerateCommand holds the parsed flag values and the injected token
// generation behavior.
type tokenGenerateCommand struct {
	generate TokenGenerate

	config   string
	subject  string
	username string
	email    string
	audience []string
	ttlRaw   string
	ttlSet   bool
}

// newTokenCommand builds the `token` parent command with the generate and
// validate subcommands.
func newTokenCommand(
	generate TokenGenerate,
	validate TokenValidate,
) *cobra.Command {
	tokenCommand := &cobra.Command{
		Use:   "token",
		Short: "Token commands",
	}

	tokenCommand.AddCommand(
		newTokenGenerateCommand(
			generate,
		),
	)

	tokenCommand.AddCommand(
		newTokenValidateCommand(
			validate,
		),
	)

	return tokenCommand
}

// newTokenGenerateCommand builds the `token generate` command.
func newTokenGenerateCommand(
	generate TokenGenerate,
) *cobra.Command {
	cmd := &tokenGenerateCommand{
		generate: generate,
	}

	command := &cobra.Command{
		Use:   "generate",
		Short: "Generate a signed JWT",
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
		&cmd.subject,
		"subject",
		"",
		"token subject (required)",
	)
	_ = command.MarkFlagRequired(
		"subject",
	)

	command.Flags().StringVar(
		&cmd.username,
		"username",
		"",
		"optional username claim",
	)

	command.Flags().StringVar(
		&cmd.email,
		"email",
		"",
		"optional email claim",
	)

	command.Flags().StringSliceVar(
		&cmd.audience,
		"audience",
		nil,
		"audience claim entries",
	)

	// A custom flag value is used to distinguish an omitted --ttl from an
	// explicitly provided value, including zero. Duration parsing belongs to
	// the CLI boundary, while semantic TTL policy remains the responsibility
	// of the generation use case.
	command.Flags().Var(
		&ttlFlag{
			cmd: cmd,
		},
		"ttl",
		"token time-to-live (e.g. 1h)",
	)

	return command
}

// run executes token generation and writes the generated token only to the
// command output stream.
func (c *tokenGenerateCommand) run(
	command *cobra.Command,
	_ []string,
) error {
	request := token.GenerateRequest{
		Subject:  c.subject,
		Username: c.username,
		Email:    c.email,
		Audience: c.audience,
	}

	if c.ttlSet {
		ttl, err := time.ParseDuration(
			c.ttlRaw,
		)
		if err != nil {
			return fmt.Errorf(
				"parse --ttl: %w",
				err,
			)
		}

		request.TTL = &ttl
	}

	generatedToken, err := c.generate.Generate(
		command.Context(),
		c.config,
		request,
	)
	if err != nil {
		return fmt.Errorf(
			"generate token: %w",
			err,
		)
	}

	output, err := json.MarshalIndent(
		generatedToken,
		"",
		"  ",
	)
	if err != nil {
		return fmt.Errorf(
			"encode generated token output: %w",
			err,
		)
	}

	if _, err := fmt.Fprintln(
		command.OutOrStdout(),
		string(output),
	); err != nil {
		return fmt.Errorf(
			"write generated token: %w",
			err,
		)
	}

	return nil
}

// ttlFlag is a pflag.Value that records whether --ttl was explicitly set.
type ttlFlag struct {
	cmd *tokenGenerateCommand
}

// String implements pflag.Value.
func (f *ttlFlag) String() string {
	return f.cmd.ttlRaw
}

// Set implements pflag.Value.
func (f *ttlFlag) Set(
	value string,
) error {
	f.cmd.ttlRaw = strings.TrimSpace(
		value,
	)
	f.cmd.ttlSet = true

	return nil
}

// Type implements pflag.Value.
func (f *ttlFlag) Type() string {
	return "duration"
}
