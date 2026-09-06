package cli

import (
	"fmt"

	cliconfig "simple-jwt-authenticator/internal/config/cli"
	"simple-jwt-authenticator/internal/jwt/key"
)

// newVerificationProvider constructs the verification-key provider required by
// JWT parsing.
//
// The CLI configuration has already passed command-specific semantic
// validation. Key loading still performs its own source-invariant checks at
// the cryptographic boundary.
func newVerificationProvider(
	jwtConfig cliconfig.JWT,
) (key.VerificationProvider, error) {
	publicKey, err := key.LoadPublic(
		jwtConfig.PublicKeyPEM,
		jwtConfig.PublicKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"load public verification key: %w",
			err,
		)
	}

	return key.NewStaticVerificationProvider(
		publicKey,
	), nil
}

// newSigningProvider constructs the signing-key provider required by JWT
// generation.
//
// Private key material is loaded only for CLI signing operations. The server
// configuration contract does not expose signing material.
func newSigningProvider(
	jwtConfig cliconfig.JWT,
) (key.SigningProvider, error) {
	privateKey, err := key.LoadPrivate(
		jwtConfig.PrivateKeyPEM,
		jwtConfig.PrivateKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"load private signing key: %w",
			err,
		)
	}

	return key.NewStaticSigningProvider(
		privateKey,
	), nil
}
