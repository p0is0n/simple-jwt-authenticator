// Package claimexpression owns extraction of dynamic claim policy from HTTP
// requests.
//
// It translates HTTP-specific representations into the transport-independent
// claim.Expression consumed by authentication.
//
// HTTP source details must not leak into the authentication or token packages.
package claimexpression

// Source identifies a bounded HTTP source from which a claim expression was
// extracted.
type Source string

const (
	// SourceQuery indicates that the expression came from an HTTP query
	// parameter.
	SourceQuery Source = "query"

	// SourceHeader indicates that the expression came from an HTTP header.
	SourceHeader Source = "header"

	// SourceUnknown indicates that no concrete source is available.
	SourceUnknown Source = "unknown"
)
