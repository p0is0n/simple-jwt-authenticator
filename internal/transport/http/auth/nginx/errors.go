package nginx

import "errors"

var (
	// errInvalidHandlerConfiguration indicates invalid mandatory dependency
	// wiring detected while constructing the adapter.
	errInvalidHandlerConfiguration = errors.New(
		"invalid nginx authentication handler configuration",
	)

	// errMissingIdentitySubject indicates that the adapter received an
	// authenticated identity that cannot safely be exposed because the required
	// subject is absent.
	errMissingIdentitySubject = errors.New(
		"authenticated identity subject is missing",
	)

	// errUnsafeHeaderValue indicates that a claim-derived value cannot safely be
	// represented as an HTTP response header field value.
	errUnsafeHeaderValue = errors.New(
		"unsafe authentication header value",
	)
)
