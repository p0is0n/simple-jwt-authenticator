package validator

import (
	"context"
	"time"
)

// Expiration validates that the token has not expired.
//
// An expiration claim is required. Skew extends the acceptance window for
// recently expired tokens.
type Expiration struct {
	Now  func() time.Time
	Skew time.Duration
}

// Validate implements Validator.
func (e Expiration) Validate(
	_ context.Context,
	request Request,
) error {
	expiresAt := request.Token.Claims.ExpiresAt
	if expiresAt == nil {
		return ErrMissingClaim
	}

	if !expiresAt.After(e.Now().Add(-e.Skew)) {
		return ErrExpired
	}

	return nil
}
