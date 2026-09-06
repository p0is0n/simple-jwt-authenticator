package validator

import (
	"context"
	"time"
)

// NotBefore validates that the token is active.
//
// An absent not-before claim is accepted. Skew allows a token to become
// active slightly before its declared activation time.
type NotBefore struct {
	Now  func() time.Time
	Skew time.Duration
}

// Validate implements Validator.
func (n NotBefore) Validate(
	_ context.Context,
	request Request,
) error {
	notBefore := request.Token.Claims.NotBefore
	if notBefore == nil {
		return nil
	}

	if notBefore.After(n.Now().Add(n.Skew)) {
		return ErrNotActive
	}

	return nil
}
