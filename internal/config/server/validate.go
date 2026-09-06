package server

import (
	"errors"
	"fmt"

	"simple-jwt-authenticator/internal/config"
	"simple-jwt-authenticator/internal/config/validation"
)

// Validate performs complete semantic validation of server configuration.
func Validate(
	appConfig Config,
) error {
	validationErrors := errors.Join(
		validateHTTPServer(
			appConfig.Server,
		),
		validateJWT(
			appConfig.JWT,
		),
		validateAuth(
			appConfig.Auth,
		),
		validateMetrics(
			appConfig.Metrics,
		),
		validation.ValidateLogging(
			appConfig.Logging,
		),
	)

	if validationErrors == nil {
		return nil
	}

	return fmt.Errorf(
		"%w: %w",
		config.ErrInvalidConfig,
		validationErrors,
	)
}
