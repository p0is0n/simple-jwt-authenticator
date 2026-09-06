// Package token defines implementation-independent contracts for parsing,
// validating, and generating authentication tokens.
//
// The package operates on normalized token representations and must not
// depend on concrete token formats, cryptographic libraries, or transport
// concerns.
package token

import "simple-jwt-authenticator/internal/token/claim"

// Value is the serialized representation of a token.
type Value string

// Token contains normalized token claims.
type Token struct {
	Claims claim.Claims
}

// SerializedToken contains the serialized token value and its normalized
// claims.
type SerializedToken struct {
	Value  Value
	Claims claim.Claims
}
