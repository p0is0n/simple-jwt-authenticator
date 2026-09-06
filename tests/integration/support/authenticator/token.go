//go:build integration

package authenticator

import (
	"context"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"simple-jwt-authenticator/internal/jwt"
	"simple-jwt-authenticator/internal/jwt/key"
	"simple-jwt-authenticator/internal/token"
)

// TokenBuilder creates signed JWTs for integration tests.
//
// Valid tokens are produced by the project's production jwt.Generator so
// the tests exercise the real signing implementation. Intentionally
// invalid tokens, such as already-expired ones, cannot be created through
// the production generator because it correctly rejects such states, so
// GenerateExpired signs directly with the JWT library instead. This
// distinction is intentional and must be kept obvious.
type TokenBuilder struct {
	generator  token.Generator
	privateKey *rsa.PrivateKey
	issuer     string
}

// NewTokenBuilder constructs a TokenBuilder that signs with the given RSA
// private key and issuer.
func NewTokenBuilder(
	privateKey *rsa.PrivateKey,
	issuer string,
) (*TokenBuilder, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	signingProvider := key.NewStaticSigningProvider(privateKey)

	// TTL bounds mirror the integration-test authenticator
	// configuration: default TTL 1h, maximum TTL 168h.
	generator, err := jwt.NewGenerator(
		signingProvider,
		jwt.AlgorithmRS256,
		issuer,
		time.Hour,
		168*time.Hour,
	)
	if err != nil {
		return nil, fmt.Errorf("create token generator: %w", err)
	}

	return &TokenBuilder{
		generator:  generator,
		privateKey: privateKey,
		issuer:     issuer,
	}, nil
}

// Generate builds a valid signed token through the production generator.
// A nil TTL selects the configured default.
func (b *TokenBuilder) Generate(
	t testing.TB,
	subject string,
	username string,
	email string,
	audience []string,
	ttl *time.Duration,
) string {
	t.Helper()

	signed, err := b.generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject:  subject,
			Username: username,
			Email:    email,
			Audience: audience,
			TTL:      ttl,
		},
	)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	return string(signed.Value)
}

// GenerateExpired builds a token that expired one hour ago. It signs
// directly with the JWT library and bypasses the production generator
// on purpose: the generator correctly refuses to create already-expired
// tokens, so this helper exists only for this invalid state.
func (b *TokenBuilder) GenerateExpired(
	t testing.TB,
	subject string,
	audience []string,
) string {
	t.Helper()

	now := time.Now().UTC()
	past := now.Add(-time.Hour)

	registered := jwtlib.RegisteredClaims{
		Issuer:    b.issuer,
		Subject:   subject,
		Audience:  jwtlib.ClaimStrings(audience),
		ExpiresAt: jwtlib.NewNumericDate(past),
		NotBefore: jwtlib.NewNumericDate(past),
		IssuedAt:  jwtlib.NewNumericDate(past),
	}

	jwtToken := jwtlib.NewWithClaims(
		jwtlib.SigningMethodRS256,
		registered,
	)

	signed, err := jwtToken.SignedString(b.privateKey)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	return signed
}
