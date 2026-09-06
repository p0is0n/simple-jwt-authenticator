// Package main is the CLI binary entrypoint.
//
// It remains intentionally thin: it invokes the CLI composition root,
// reports fatal errors and selects the process exit code. Concrete dependency
// wiring belongs to internal/app/cli. Process termination belongs only here.
package main

import (
	"context"
	"fmt"
	"os"

	app "simple-jwt-authenticator/internal/app/cli"
)

func main() {
	if err := app.Run(
		context.Background(),
		os.Args[1:],
	); err != nil {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"cli: %v\n",
			err,
		)

		os.Exit(1)
	}
}
