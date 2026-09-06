// Package cli is the CLI composition root.
//
// It owns concrete dependency wiring for CLI commands. The presentation
// package internal/cli receives command behaviors through interfaces and must
// not know concrete configuration schemas, JWT implementations, key
// providers or validator construction.
package cli

import (
	"context"
	"os"

	transport "simple-jwt-authenticator/internal/transport/cli"
)

// Run constructs and executes the CLI application.
//
// Dependency construction belongs here rather than to internal/cli so the
// Cobra adapter remains independent from concrete infrastructure.
//
// Process termination remains the responsibility of the outer executable
// entrypoint. Run returns errors and never calls os.Exit.
func Run(
	ctx context.Context,
	args []string,
) error {
	app := transport.New(
		configValidate{},
		tokenGenerate{},
		tokenValidate{},
	)

	return app.Execute(
		ctx,
		args,
		os.Stdout,
		os.Stderr,
	)
}
