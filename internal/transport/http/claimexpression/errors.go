package claimexpression

import "errors"

var (
	// ErrMalformedExpression indicates that a configured HTTP source contains
	// an empty, syntactically invalid or otherwise unusable claim expression.
	ErrMalformedExpression = errors.New(
		"malformed claim expression",
	)

	// ErrMultipleExpressions indicates that more than one HTTP source supplied
	// a claim expression for the same request.
	//
	// Claim-policy sources deliberately have no implicit precedence. Accepting
	// one source while silently ignoring another could make authorization
	// behavior dependent on transport ordering.
	ErrMultipleExpressions = errors.New(
		"multiple claim expressions",
	)

	// ErrNoExtractors indicates invalid provider construction without any HTTP
	// claim-expression source.
	ErrNoExtractors = errors.New(
		"no claim expression extractors configured",
	)

	// ErrInvalidExtractorResult indicates a violated extractor contract.
	//
	// This represents an internal programming or wiring error rather than
	// malformed client input.
	ErrInvalidExtractorResult = errors.New(
		"invalid claim expression extractor result",
	)
)
