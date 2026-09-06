package key

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
)

// StaticSigningProvider holds immutable RSA signing material.
//
// The key is validated once during provider construction and is never
// reparsed for individual signing operations.
type StaticSigningProvider struct {
	privateKey *rsa.PrivateKey
	keyErr     error
}

// NewStaticSigningProvider constructs a provider from an RSA private key.
func NewStaticSigningProvider(
	privateKey *rsa.PrivateKey,
) *StaticSigningProvider {
	return &StaticSigningProvider{
		privateKey: privateKey,
		keyErr:     validateRSAPrivateKey(privateKey),
	}
}

// Provide returns signing material only for the explicitly supported
// algorithm and a key satisfying the RSA security policy.
func (p *StaticSigningProvider) Provide(
	_ context.Context,
	request SigningRequest,
) (crypto.Signer, error) {
	if p == nil {
		return nil, ErrInvalidRSAKey
	}

	if p.keyErr != nil {
		return nil, p.keyErr
	}

	if !isSupportedAlgorithm(request.Algorithm) {
		return nil, fmt.Errorf(
			"%w: %q",
			ErrUnsupportedAlgorithm,
			request.Algorithm,
		)
	}

	return p.privateKey, nil
}
