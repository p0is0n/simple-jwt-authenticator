// Package jwt is the concrete JWT implementation. It may depend on the
// selected JWT library. Third-party JWT types must not escape this package.
package jwt

import (
	"fmt"

	"simple-jwt-authenticator/internal/token"
)

// Algorithm identifies a JWT signing algorithm supported by this
// implementation.
type Algorithm string

const (
	// AlgorithmRS256 is RSA with SHA-256.
	AlgorithmRS256 Algorithm = "RS256"
)

// ParseAlgorithm parses an algorithm name and rejects values outside the
// explicitly supported set.
func ParseAlgorithm(value string) (Algorithm, error) {
	algorithm := Algorithm(value)
	if err := algorithm.validate(); err != nil {
		return "", err
	}

	return algorithm, nil
}

// String returns the JWT algorithm name.
func (a Algorithm) String() string {
	return string(a)
}

// validate verifies that the algorithm belongs to the closed set supported
// by this implementation.
//
// Algorithm is string-backed and can therefore be constructed without
// ParseAlgorithm. Security-sensitive constructors must call validate rather
// than assuming that a typed value is trusted.
func (a Algorithm) validate() error {
	switch a {
	case AlgorithmRS256:
		return nil

	default:
		return fmt.Errorf(
			"%w: %q",
			token.ErrUnsupportedAlgorithm,
			string(a),
		)
	}
}
