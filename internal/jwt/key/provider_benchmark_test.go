package key

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func BenchmarkStaticVerificationProvider_Provide(
	b *testing.B,
) {
	privateKey := benchmarkRSAKey(b)

	provider := NewStaticVerificationProvider(
		&privateKey.PublicKey,
	)

	request := VerificationRequest{
		Algorithm: "RS256",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		publicKey, err := provider.Provide(
			ctx,
			request,
		)
		if err != nil {
			b.Fatalf(
				"Provide() error = %v, want nil",
				err,
			)
		}

		if publicKey == nil {
			b.Fatal(
				"Provide() key = nil, want non-nil",
			)
		}
	}
}

func BenchmarkStaticSigningProvider_Provide(
	b *testing.B,
) {
	privateKey := benchmarkRSAKey(b)

	provider := NewStaticSigningProvider(
		privateKey,
	)

	request := SigningRequest{
		Algorithm: "RS256",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		signer, err := provider.Provide(
			ctx,
			request,
		)
		if err != nil {
			b.Fatalf(
				"Provide() error = %v, want nil",
				err,
			)
		}

		if signer == nil {
			b.Fatal(
				"Provide() signer = nil, want non-nil",
			)
		}
	}
}

func benchmarkRSAKey(
	b *testing.B,
) *rsa.PrivateKey {
	b.Helper()

	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		minimumRSAKeyBits,
	)
	if err != nil {
		b.Fatalf(
			"rsa.GenerateKey() error = %v, want nil",
			err,
		)
	}

	return privateKey
}
