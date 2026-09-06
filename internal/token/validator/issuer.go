package validator

import "context"

// Issuer validates the token issuer against an expected value.
//
// An empty expected issuer disables issuer validation.
type Issuer struct {
	Expected string
}

// Validate implements Validator.
func (i Issuer) Validate(
	_ context.Context,
	request Request,
) error {
	if i.Expected == "" {
		return nil
	}

	if request.Token.Claims.Issuer != i.Expected {
		return ErrInvalidIssuer
	}

	return nil
}
