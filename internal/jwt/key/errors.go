// Package key owns verification and signing key-provider contracts and
// strict PEM parsing.
package key

import "errors"

var (
	// ErrInvalidPEM indicates that PEM input is absent, malformed, or
	// contains ambiguous trailing material.
	ErrInvalidPEM = errors.New("invalid PEM")

	// ErrUnexpectedKey indicates that decoded key material is not of the
	// expected key type.
	ErrUnexpectedKey = errors.New("unexpected key type")

	// ErrInvalidRSAKey indicates that an RSA key does not satisfy structural
	// or cryptographic-strength requirements.
	ErrInvalidRSAKey = errors.New("invalid RSA key")

	// ErrUnsupportedAlgorithm indicates that a key provider was asked for
	// material for an algorithm outside its supported policy.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm for key")
)
