package claimexpression

import "simple-jwt-authenticator/internal/token/claim"

// Extraction is the raw result returned by an HTTP claim-expression extractor.
//
// An extractor returns exactly one of:
//
//   - NotApplicable=true when its source is absent;
//   - Extracted=true with Value populated when its source is present.
//
// A present but malformed source is represented by an error.
type Extraction struct {
	// Value contains the raw expression exactly as supplied by the HTTP source.
	Value string

	// Source identifies the bounded HTTP source inspected by the extractor.
	Source Source

	// Extracted reports that this source supplied an expression.
	Extracted bool

	// NotApplicable reports that this source was absent from the request.
	NotApplicable bool
}

// Result is the normalized provider result.
//
// Expression contains a parsed, transport-independent policy only when
// Extracted is true.
type Result struct {
	Expression claim.Expression
	Source     Source
	Extracted  bool
}
