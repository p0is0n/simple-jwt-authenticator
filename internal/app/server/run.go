// Package server is the HTTP server composition root.
//
// It owns explicit construction of the concrete application graph used by the
// server process. Transport mechanics remain in internal/transport/http,
// configuration lifecycle remains in internal/config/server, and
// authentication policy remains visible here through explicit wiring.
//
// This package must not hide construction behind a service locator, generic
// factory registry, reflection-based container or framework.
package server

import (
	"context"
	"fmt"

	"simple-jwt-authenticator/internal/buildinfo"
	serverconfig "simple-jwt-authenticator/internal/config/server"
	"simple-jwt-authenticator/internal/logging"
	transport "simple-jwt-authenticator/internal/transport/http"
)

// Run loads the validated server configuration, constructs the complete
// application graph and runs the HTTP server until its context is cancelled.
func Run(
	ctx context.Context,
	configPath string,
) error {
	if ctx == nil {
		return fmt.Errorf(
			"run server: context must not be nil",
		)
	}

	appConfig, err := serverconfig.LoadValidated(
		configPath,
	)
	if err != nil {
		return err
	}

	logger, err := logging.New(
		appConfig.Logging,
	)
	if err != nil {
		return fmt.Errorf(
			"create logger: %w",
			err,
		)
	}

	authenticator, err := newAuthenticator(
		appConfig.JWT,
	)
	if err != nil {
		return fmt.Errorf(
			"create authenticator: %w",
			err,
		)
	}

	credentialProvider, err := newCredentialProvider(
		appConfig.Auth,
	)
	if err != nil {
		return fmt.Errorf(
			"create credential provider: %w",
			err,
		)
	}

	claimExpressionProvider, err := newClaimExpressionProvider()
	if err != nil {
		return fmt.Errorf(
			"create claim expression provider: %w",
			err,
		)
	}

	observability := newObservability(
		appConfig.Metrics,
	)

	router, err := newRouter(
		appConfig.Auth.Handlers.HTTP.Nginx.Enabled,
		authenticator,
		credentialProvider,
		claimExpressionProvider,
		observability,
		logger,
	)
	if err != nil {
		return fmt.Errorf(
			"create router: %w",
			err,
		)
	}

	handler := transport.NewHandler(
		logger,
		observability.Requests,
		router.Handler(),
	)

	httpServer, err := transport.NewServer(
		appConfig.Server,
		handler,
		logger,
	)
	if err != nil {
		return fmt.Errorf(
			"create HTTP server: %w",
			err,
		)
	}

	build := buildinfo.Current()
	logger.InfoContext(
		ctx,
		"starting server",
		"version",
		build.Version,
		"commit",
		build.Commit,
	)

	if err := httpServer.Run(
		ctx,
	); err != nil {
		return fmt.Errorf(
			"run HTTP server: %w",
			err,
		)
	}

	return nil
}
