package parser

import "errors"

// Parser errors classify failures produced while converting textual claim
// policy into a validated claim expression.
//
// Errors originating from the claim package are preserved through wrapping so
// callers may continue to classify semantic policy failures with errors.Is.
var (
	// ErrSyntax indicates that a textual claim expression does not conform to
	// the supported expression grammar.
	ErrSyntax = errors.New(
		"invalid claim expression syntax",
	)

	// ErrExpressionTooLarge indicates that the textual representation exceeds
	// the maximum size accepted by the parser.
	//
	// The limit is enforced before lexical analysis so excessively large
	// untrusted inputs cannot consume disproportionate parser resources.
	ErrExpressionTooLarge = errors.New(
		"claim expression too large",
	)
)
