package server

import (
	"fmt"
	"time"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/config"
	"simple-jwt-authenticator/internal/jwt"
	"simple-jwt-authenticator/internal/jwt/key"
	"simple-jwt-authenticator/internal/token/validator"
)

// newAuthenticator constructs the transport-independent authentication core
// used by the HTTP server.
//
// The server accepts verification configuration only. There is deliberately no
// path from the server composition root to private signing material.
//
// Validator ordering is security-sensitive and must remain explicit:
//
//	RequiredClaims
//	Expiration
//	NotBefore
//	IssuedAt
//	Issuer
//	Audience
func newAuthenticator(
	jwtConfig config.JWTVerification,
) (*authentication.Authenticator, error) {
	algorithm, err := jwt.ParseAlgorithm(
		jwtConfig.Algorithm,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse JWT algorithm: %w",
			err,
		)
	}

	verificationProvider, err := newVerificationProvider(
		jwtConfig,
	)
	if err != nil {
		return nil, err
	}

	parser, err := jwt.NewParser(
		verificationProvider,
		algorithm,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create JWT parser: %w",
			err,
		)
	}

	clock := time.Now

	validators := validator.NewProvider(
		validator.RequiredClaims{},
		validator.Expiration{
			Now:  clock,
			Skew: jwtConfig.ClockSkew.Std(),
		},
		validator.NotBefore{
			Now:  clock,
			Skew: jwtConfig.ClockSkew.Std(),
		},
		validator.IssuedAt{
			Now:  clock,
			Skew: jwtConfig.ClockSkew.Std(),
		},
		validator.Issuer{
			Expected: jwtConfig.Issuer,
		},
		validator.Audience{
			Expected: jwtConfig.Audience,
		},
	)

	authenticator, err := authentication.NewAuthenticator(
		parser,
		validators,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"construct authentication core: %w",
			err,
		)
	}

	return authenticator, nil
}

// newVerificationProvider constructs the immutable verification provider used
// by the server.
//
// Only public key configuration is accepted by this function. The server
// composition root therefore cannot accidentally construct a signing
// provider.
func newVerificationProvider(
	jwtConfig config.JWTVerification,
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
