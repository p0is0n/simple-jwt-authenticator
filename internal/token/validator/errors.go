package validator

import "errors"

// Validation errors identify policy and validation-chain failures without
// requiring callers to inspect human-readable error messages.
var (
	// ErrNoValidators indicates that no validation rules are configured.
	//
	// An empty validation chain must fail closed because otherwise every
	// successfully parsed token would pass application-level validation.
	ErrNoValidators = errors.New("no validators configured")

	// ErrMissingClaim indicates that a required claim is absent.
	ErrMissingClaim = errors.New("missing required claim")

	// ErrExpired indicates that the token has expired.
	ErrExpired = errors.New("token expired")

	// ErrNotActive indicates that the token is not active yet.
	ErrNotActive = errors.New("token not active yet")

	// ErrIssuedAtFuture indicates that the token was issued in the future
	// beyond the allowed clock skew.
	ErrIssuedAtFuture = errors.New("token issued in the future")

	// ErrInvalidIssuer indicates that the issuer does not match the expected
	// issuer.
	ErrInvalidIssuer = errors.New("invalid issuer")

	// ErrInvalidAudience indicates that none of the token audiences match an
	// expected audience.
	ErrInvalidAudience = errors.New("invalid audience")

	// ErrClaimExpressionNotSatisfied indicates that a valid claim expression
	// evaluated to false for the token being validated.
	//
	// The error intentionally does not identify the failed branch or claim so
	// callers do not need to expose policy details when reporting an
	// authentication failure.
	ErrClaimExpressionNotSatisfied = errors.New(
		"claim expression not satisfied",
	)
)
