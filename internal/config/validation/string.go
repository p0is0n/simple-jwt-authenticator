package validation

import (
	"fmt"
	"strings"
)

// CanonicalNonEmptyString validates identifier-like configuration values.
//
// Leading and trailing whitespace is rejected rather than normalized so the
// value visible to the operator is exactly the value used by the application.
func CanonicalNonEmptyString(
	field string,
	value string,
) error {
	trimmed := strings.TrimSpace(value)

	if trimmed == "" {
		return fmt.Errorf(
			"%s must be non-empty",
			field,
		)
	}

	if trimmed != value {
		return fmt.Errorf(
			"%s must not contain leading or trailing whitespace",
			field,
		)
	}

	return nil
}
