package cli

import (
	"errors"
	"fmt"

	"simple-jwt-authenticator/internal/config"
)

// Validate performs complete semantic validation of CLI configuration.
//
// Unlike command-specific validators, Validate requires the complete CLI
// configuration to support both JWT verification and JWT generation.
func Validate(
	appConfig Config,
) error {
	validationErrors := errors.Join(
		validateTokenValidateJWT(
			appConfig.JWT,
		),
		validateTokenGenerateJWT(
			appConfig.JWT,
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

// ValidateTokenGenerate validates configuration required to generate JWTs.
func ValidateTokenGenerate(
	appConfig Config,
) error {
	if err := validateTokenGenerateJWT(
		appConfig.JWT,
	); err != nil {
		return fmt.Errorf(
			"%w: %w",
			config.ErrInvalidConfig,
			err,
		)
	}

	return nil
}

// ValidateTokenValidate validates configuration required to verify JWTs.
func ValidateTokenValidate(
	appConfig Config,
) error {
	if err := validateTokenValidateJWT(
		appConfig.JWT,
	); err != nil {
		return fmt.Errorf(
			"%w: %w",
			config.ErrInvalidConfig,
			err,
		)
	}

	return nil
}
