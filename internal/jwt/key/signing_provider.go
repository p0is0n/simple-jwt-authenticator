package key

import (
	"context"
	"crypto"
)

// SigningProvider supplies signing key material for a given algorithm.
// The CLI token-generation flow uses signing material; the HTTP server
// must never construct a signing provider.
//
// Providers must be safe for concurrent use.
type SigningProvider interface {
	Provide(
		ctx context.Context,
		request SigningRequest,
	) (crypto.Signer, error)
}
