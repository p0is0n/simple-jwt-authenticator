// Package main is the server binary entrypoint.
//
// It remains intentionally thin: process execution is delegated to runMain,
// while main itself performs only the final process termination.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	app "simple-jwt-authenticator/internal/app/server"
)

func main() {
	os.Exit(
		runMain(
			os.Args[1:],
		),
	)
}

// runMain owns the outer process lifecycle.
//
// Keeping os.Exit out of this function guarantees that deferred cleanup,
// including signal-context deregistration, always runs before the process
// terminates.
func runMain(
	args []string,
) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(
			os.Stderr,
			"usage: server <config-path>",
		)

		return 2
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := run(
		ctx,
		args[0],
	); err != nil {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"server: %v\n",
			err,
		)

		return 1
	}

	return 0
}

// run delegates execution to the server composition root.
//
// Process-global concerns such as os.Args, signal subscription, stderr and
// exit codes remain outside this boundary. Accepting an explicit context and
// configuration path keeps application execution independently testable.
func run(
	ctx context.Context,
	configPath string,
) error {
	return app.Run(
		ctx,
		configPath,
	)
}
