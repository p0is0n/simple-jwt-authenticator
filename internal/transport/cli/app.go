// Package cli implements the command-line transport adapter.
//
// It owns Cobra commands, argument and flag parsing, command output and the
// translation of CLI input into injected application behaviors. It does not
// construct concrete JWT, key, configuration or authentication dependencies.
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"simple-jwt-authenticator/internal/buildinfo"
)

// App is the root CLI application. It wires commands to their dependencies
// which are supplied by the composition root.
type App struct {
	root *cobra.Command
}

// New constructs the CLI application from injected command behaviors.
func New(
	configValidate ConfigValidate,
	tokenGenerate TokenGenerate,
	tokenValidate TokenValidate,
) *App {
	root := &cobra.Command{
		Use:   "simple-jwt-authenticator",
		Short: "JWT authentication backend CLI",
	}

	root.AddCommand(
		newConfigCommand(
			configValidate,
		),
	)

	root.AddCommand(
		newTokenCommand(
			tokenGenerate,
			tokenValidate,
		),
	)

	root.AddCommand(
		newVersionCommand(),
	)

	return &App{
		root: root,
	}
}

// Execute runs the CLI with the supplied context and arguments.
//
// The context is installed on the root Cobra command so cancellation,
// deadlines and request-scoped values propagate through command.Context()
// into injected application behaviors.
//
// Process termination belongs to the outer executable entrypoint; this method
// always returns errors instead of calling os.Exit.
func (a *App) Execute(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if ctx == nil {
		return fmt.Errorf(
			"execute CLI: context must not be nil",
		)
	}

	a.root.SetContext(
		ctx,
	)

	a.root.SetArgs(
		args,
	)

	a.root.SetOut(
		stdout,
	)

	a.root.SetErr(
		stderr,
	)

	return a.root.Execute()
}

// versionString formats build information for the version command.
func versionString(
	info buildinfo.Info,
) string {
	return fmt.Sprintf(
		"simple-jwt-authenticator %s (commit: %s, date: %s)\n",
		info.Version,
		info.Commit,
		info.Date,
	)
}
