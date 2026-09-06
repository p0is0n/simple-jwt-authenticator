package validator

import "context"

// RequiredClaims enforces claims required by the authentication policy.
//
// Subject is the stable required identity. Human-friendly identity fields
// such as username and email remain optional.
type RequiredClaims struct{}

// Validate implements Validator.
func (RequiredClaims) Validate(
	_ context.Context,
	request Request,
) error {
	if request.Token.Claims.Subject == "" {
		return ErrMissingClaim
	}

	return nil
}
