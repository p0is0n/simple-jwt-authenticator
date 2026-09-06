package validator

import (
	"context"
	"slices"
)

// Audience validates that at least one token audience matches an expected
// audience.
//
// An empty expected audience set disables audience validation. Matching uses
// exact string equality over normalized claim values.
type Audience struct {
	Expected []string
}

// Validate implements Validator.
func (a Audience) Validate(
	_ context.Context,
	request Request,
) error {
	if len(a.Expected) == 0 {
		return nil
	}

	actual := request.Token.Claims.Audience
	if len(actual) == 0 {
		return ErrInvalidAudience
	}

	for _, expected := range a.Expected {
		if slices.Contains(
			actual,
			expected,
		) {
			return nil
		}
	}

	return ErrInvalidAudience
}
