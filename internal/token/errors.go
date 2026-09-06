package token

import "errors"

// Token processing errors. Callers can classify these errors with errors.Is
// without depending on human-readable error messages.
var (
	// ErrMalformedToken indicates that a credential could not be parsed as
	// a structurally valid token.
	ErrMalformedToken = errors.New("malformed token")

	// ErrUnsupportedAlgorithm indicates that the token uses an algorithm
	// that is not permitted by the configured policy.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

	// ErrInvalidSignature indicates that signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidClaims indicates that token claims could not be normalized
	// from their encoded representation.
	ErrInvalidClaims = errors.New("invalid claims")
)
