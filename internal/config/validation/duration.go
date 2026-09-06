// Package validation provides reusable semantic validation rules for
// configuration values shared by application-specific configuration packages.
package validation

import (
	"fmt"

	"simple-jwt-authenticator/internal/config"
)

// PositiveDuration requires a duration greater than zero.
func PositiveDuration(
	field string,
	duration config.Duration,
) error {
	if duration.Std() <= 0 {
		return fmt.Errorf(
			"%s must be positive, got %s",
			field,
			duration,
		)
	}

	return nil
}

// NonNegativeDuration permits zero but rejects negative durations.
func NonNegativeDuration(
	field string,
	duration config.Duration,
) error {
	if duration.Std() < 0 {
		return fmt.Errorf(
			"%s must be non-negative, got %s",
			field,
			duration,
		)
	}

	return nil
}
