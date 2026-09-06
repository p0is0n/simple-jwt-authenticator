package credential

import "simple-jwt-authenticator/internal/authentication"

// Result describes the non-error outcome of HTTP credential extraction.
//
// An extractor can either:
//
//   - report itself as not applicable to the request;
//   - return an extracted credential.
//
// A credential source that is present but malformed is represented by a
// terminal error rather than a Result state.
type Result struct {
	// Credential is the transport-neutral authentication credential.
	// It is populated only when Extracted is true.
	Credential authentication.Credential

	// Source identifies the bounded HTTP credential source inspected by the
	// extractor.
	Source Source

	// Extracted reports whether a credential was successfully extracted.
	Extracted bool

	// NotApplicable reports that the extractor does not apply to the
	// request, for example because its credential source was absent.
	NotApplicable bool
}
