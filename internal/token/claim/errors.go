package claim

import "errors"

// Expression construction errors.
//
// Expressions are validated when constructed so malformed or excessively
// complex policies cannot reach authentication evaluation.
var (
	// ErrInvalidName indicates that an expression references a claim that is
	// not supported by request-scoped claim policy.
	ErrInvalidName = errors.New(
		"invalid claim name",
	)

	// ErrInvalidOperator indicates that an expression uses an unsupported
	// comparison operator.
	ErrInvalidOperator = errors.New(
		"invalid claim operator",
	)

	// ErrEmptyMatchValue indicates that a comparison was constructed without
	// an expected value.
	ErrEmptyMatchValue = errors.New(
		"empty claim match value",
	)

	// ErrInvalidRegex indicates that a regex comparison contains an invalid
	// regular expression.
	ErrInvalidRegex = errors.New(
		"invalid claim regex",
	)

	// ErrInvalidExpression indicates that a logical expression has an invalid
	// structure.
	ErrInvalidExpression = errors.New(
		"invalid claim expression",
	)

	// ErrExpressionTooComplex indicates that an expression exceeds the
	// configured structural limits.
	ErrExpressionTooComplex = errors.New(
		"claim expression too complex",
	)
)
