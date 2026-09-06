package credential

import "errors"

var (
	// ErrMissingCredential is returned when none of the configured
	// extractors produced a credential for the request.
	ErrMissingCredential = errors.New("missing credential")

	// ErrNoExtractors is returned when a credential provider is constructed
	// without any extractors.
	ErrNoExtractors = errors.New("no credential extractors configured")

	// ErrMalformedCredential is returned when a credential source is present
	// but its value is structurally malformed.
	ErrMalformedCredential = errors.New("malformed credential")
)
