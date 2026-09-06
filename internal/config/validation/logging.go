package validation

import (
	"errors"
	"fmt"

	"simple-jwt-authenticator/internal/config"
)

// ValidateLogging validates structured logging configuration.
func ValidateLogging(
	logging config.Logging,
) error {
	var problems []error

	switch logging.Level {
	case config.LogLevelDebug,
		config.LogLevelInfo,
		config.LogLevelWarn,
		config.LogLevelError:
		// Supported.

	default:
		problems = append(
			problems,
			fmt.Errorf(
				"logging.level must be one of debug, info, warn, error, got %q",
				logging.Level,
			),
		)
	}

	switch logging.Format {
	case config.LogFormatJSON,
		config.LogFormatText:
		// Supported.

	default:
		problems = append(
			problems,
			fmt.Errorf(
				"logging.format must be one of json, text, got %q",
				logging.Format,
			),
		)
	}

	return errors.Join(
		problems...,
	)
}
