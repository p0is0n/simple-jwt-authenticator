// Package claim defines normalized token claims and request-scoped
// expressions evaluated against them.
//
// The package is independent of concrete token formats, cryptographic
// implementations, and transport protocols. It provides the canonical claim
// representation shared by token parsing, validation, generation, and
// authentication policy evaluation.
package claim

import "time"

// Claims are normalized, implementation-independent token claims.
//
// Temporal claims use pointers so an absent claim remains distinguishable
// from the zero time.
type Claims struct {
	Subject   string
	Issuer    string
	Audience  []string
	ExpiresAt *time.Time
	IssuedAt  *time.Time
	NotBefore *time.Time
	ID        string
	Username  string
	Email     string
}
