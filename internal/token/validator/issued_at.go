package validator

import (
	"context"
	"time"
)

// IssuedAt validates that the token was not issued too far in the future.
//
// An absent issued-at claim is accepted. Skew defines the tolerated amount
// of clock difference.
type IssuedAt struct {
	Now  func() time.Time
	Skew time.Duration
}

// Validate implements Validator.
func (i IssuedAt) Validate(
	_ context.Context,
	request Request,
) error {
	issuedAt := request.Token.Claims.IssuedAt
	if issuedAt == nil {
		return nil
	}

	if issuedAt.After(i.Now().Add(i.Skew)) {
		return ErrIssuedAtFuture
	}

	return nil
}
