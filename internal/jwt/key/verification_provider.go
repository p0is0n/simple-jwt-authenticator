package key

import (
	"context"
	"crypto"
)

// VerificationProvider supplies public verification key material for a
// given algorithm. The server uses verification material only and never
// needs signing material.
//
// Providers must be safe for concurrent use.
type VerificationProvider interface {
	Provide(
		ctx context.Context,
		request VerificationRequest,
	) (crypto.PublicKey, error)
}
