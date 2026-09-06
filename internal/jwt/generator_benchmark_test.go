package jwt

import (
	"context"
	"testing"
	"time"

	"simple-jwt-authenticator/internal/jwt/key"
	"simple-jwt-authenticator/internal/token"
)

func BenchmarkGenerator_GenerateRS256(b *testing.B) {
	privateKey := testKeys(b)

	provider := key.NewStaticSigningProvider(
		privateKey,
	)

	generator, err := NewGenerator(
		provider,
		AlgorithmRS256,
		"home-auth",
		time.Hour,
		168*time.Hour,
	)
	if err != nil {
		b.Fatalf(
			"NewGenerator() error = %v, want nil",
			err,
		)
	}

	request := token.GenerateRequest{
		Subject:  "camera-front",
		Username: "front",
		Email:    "front@example.com",
		Audience: []string{
			"internal-services",
		},
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		generated, err := generator.Generate(
			ctx,
			request,
		)
		if err != nil {
			b.Fatalf(
				"Generate() error = %v, want nil",
				err,
			)
		}

		if generated.Value == "" {
			b.Fatal(
				"Generate() value = empty, want non-empty",
			)
		}
	}
}

func BenchmarkGenerator_GenerateRS256MinimalClaims(
	b *testing.B,
) {
	privateKey := testKeys(b)

	provider := key.NewStaticSigningProvider(
		privateKey,
	)

	generator, err := NewGenerator(
		provider,
		AlgorithmRS256,
		"home-auth",
		time.Hour,
		168*time.Hour,
	)
	if err != nil {
		b.Fatalf(
			"NewGenerator() error = %v, want nil",
			err,
		)
	}

	request := token.GenerateRequest{
		Subject: "camera-front",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		generated, err := generator.Generate(
			ctx,
			request,
		)
		if err != nil {
			b.Fatalf(
				"Generate() error = %v, want nil",
				err,
			)
		}

		if generated.Value == "" {
			b.Fatal(
				"Generate() value = empty, want non-empty",
			)
		}
	}
}

func BenchmarkGenerator_ResolveDefaultTTL(b *testing.B) {
	generator := &Generator{
		defaultTTL: time.Hour,
		maxTTL:     168 * time.Hour,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		ttl, err := generator.resolveTTL(nil)
		if err != nil {
			b.Fatalf(
				"resolveTTL() error = %v, want nil",
				err,
			)
		}

		if ttl != time.Hour {
			b.Fatalf(
				"resolveTTL() = %s, want %s",
				ttl,
				time.Hour,
			)
		}
	}
}

func BenchmarkGenerator_ResolveExplicitTTL(b *testing.B) {
	generator := &Generator{
		defaultTTL: time.Hour,
		maxTTL:     168 * time.Hour,
	}

	ttl := 30 * time.Minute

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		resolved, err := generator.resolveTTL(
			&ttl,
		)
		if err != nil {
			b.Fatalf(
				"resolveTTL() error = %v, want nil",
				err,
			)
		}

		if resolved != ttl {
			b.Fatalf(
				"resolveTTL() = %s, want %s",
				resolved,
				ttl,
			)
		}
	}
}
