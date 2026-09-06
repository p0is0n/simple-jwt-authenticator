package key

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
)

// StaticVerificationProvider holds immutable RSA verification material.
//
// Key policy is evaluated during construction and enforced again through
// Provide without trusting the caller to have used ParsePublic.
type StaticVerificationProvider struct {
	publicKey *rsa.PublicKey
	keyErr    error
}

// NewStaticVerificationProvider constructs a provider from an RSA public
// key.
func NewStaticVerificationProvider(
	publicKey *rsa.PublicKey,
) *StaticVerificationProvider {
	return &StaticVerificationProvider{
		publicKey: publicKey,
		keyErr:    validateRSAPublicKey(publicKey),
	}
}

// Provide returns verification material only for the explicitly supported
// algorithm and a key satisfying the RSA security policy.
func (p *StaticVerificationProvider) Provide(
	_ context.Context,
	request VerificationRequest,
) (crypto.PublicKey, error) {
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

	return p.publicKey, nil
}
