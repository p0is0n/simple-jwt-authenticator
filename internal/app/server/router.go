package server

import (
	"fmt"
	"log/slog"

	"simple-jwt-authenticator/internal/authentication"
	httptransport "simple-jwt-authenticator/internal/transport/http"
	"simple-jwt-authenticator/internal/transport/http/auth/nginx"
	"simple-jwt-authenticator/internal/transport/http/claimexpression"
	"simple-jwt-authenticator/internal/transport/http/credential"
	"simple-jwt-authenticator/internal/transport/http/health"
)

// newRouter explicitly registers the enabled server handlers.
//
// Handler registration remains visible in the composition root rather than
// being driven by reflection, init registration or a generic factory map.
func newRouter(
	nginxEnabled bool,
	authenticator *authentication.Authenticator,
	credentialProvider *credential.Provider,
	claimExpressionProvider *claimexpression.Provider,
	observability observability,
	logger *slog.Logger,
) (*httptransport.Router, error) {
	router := httptransport.NewRouter()

	if nginxEnabled {
		nginxHandler, err := nginx.NewHandler(
			authenticator,
			credentialProvider,
			claimExpressionProvider,
			observability.Authentication,
			logger,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"create Nginx authentication handler: %w",
				err,
			)
		}

		router.AddAuthHandler(
			nginxHandler,
		)
	}

	router.AddHandler(
		health.NewHandler(),
	)

	if observability.Handler != nil {
		router.AddHandler(
			observability.Handler,
		)
	}

	return router, nil
}
