package jwt

import "errors"

var (
	// errNilVerificationProvider indicates that a parser was constructed
	// without a verification provider.
	errNilVerificationProvider = errors.New("nil verification provider")

	// errNilSigningProvider indicates that a generator was constructed
	// without a signing provider.
	errNilSigningProvider = errors.New("nil signing provider")

	// errInvalidDefaultTTL indicates that the configured default token
	// lifetime is invalid.
	errInvalidDefaultTTL = errors.New("invalid default ttl")

	// errInvalidMaxTTL indicates that the configured maximum token lifetime
	// is invalid.
	errInvalidMaxTTL = errors.New("invalid maximum ttl")

	// errInvalidTTL indicates that an explicitly requested token lifetime is
	// invalid.
	errInvalidTTL = errors.New("invalid ttl")

	// errEmptySubject indicates that a generation request contains no usable
	// subject.
	errEmptySubject = errors.New("empty subject")
)
