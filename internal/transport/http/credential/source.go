// Package credential owns HTTP-specific credential extraction. The
// transport-neutral authentication.Credential carries only the token value;
// HTTP source metadata (Authorization header vs cookie) lives here and
// must not be moved into the authentication package.
package credential

// Source is the bounded HTTP credential source. It is used as a metrics
// label and mapped from HTTP-specific metadata at this boundary.
type Source string

const (
	// SourceAuthorizationHeader means the credential came from the
	// Authorization header.
	SourceAuthorizationHeader Source = "authorization_header"

	// SourceCookie means the credential came from a cookie.
	SourceCookie Source = "cookie"

	// SourceUnknown means the source could not be determined.
	SourceUnknown Source = "unknown"
)
