package jwt

import (
	"context"
	"testing"

	"simple-jwt-authenticator/internal/jwt/key"
	"simple-jwt-authenticator/internal/token"
)

func BenchmarkParser_ParseValidRS256(b *testing.B) {
	privateKey := testKeys(b)

	publicKey, err := key.ParsePublic(
		publicKeyPKIXPEM(
			b,
			privateKey,
		),
	)
	if err != nil {
		b.Fatalf(
			"ParsePublic() error = %v, want nil",
			err,
		)
	}

	parser, err := NewParser(
		key.NewStaticVerificationProvider(publicKey),
		AlgorithmRS256,
	)
	if err != nil {
		b.Fatalf(
			"NewParser() error = %v, want nil",
			err,
		)
	}

	value := token.Value(
		signValidToken(
			b,
			privateKey,
			"camera-front",
		),
	)

	request := token.ParseRequest{
		Value: value,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.SetBytes(
		int64(
			len(value),
		),
	)
	b.ResetTimer()

	for b.Loop() {
		parsed, err := parser.Parse(
			ctx,
			request,
		)
		if err != nil {
			b.Fatalf(
				"Parse() error = %v, want nil",
				err,
			)
		}

		if parsed.Claims.Subject != "camera-front" {
			b.Fatalf(
				"subject = %q, want %q",
				parsed.Claims.Subject,
				"camera-front",
			)
		}
	}
}

func BenchmarkParser_ParseInvalidSignature(b *testing.B) {
	verificationPrivateKey := testKeys(b)
	signingPrivateKey := testKeys(b)

	publicKey, err := key.ParsePublic(
		publicKeyPKIXPEM(
			b,
			verificationPrivateKey,
		),
	)
	if err != nil {
		b.Fatalf(
			"ParsePublic() error = %v, want nil",
			err,
		)
	}

	parser, err := NewParser(
		key.NewStaticVerificationProvider(publicKey),
		AlgorithmRS256,
	)
	if err != nil {
		b.Fatalf(
			"NewParser() error = %v, want nil",
			err,
		)
	}

	value := token.Value(
		signValidToken(
			b,
			signingPrivateKey,
			"camera-front",
		),
	)

	request := token.ParseRequest{
		Value: value,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.SetBytes(
		int64(
			len(value),
		),
	)
	b.ResetTimer()

	for b.Loop() {
		_, err := parser.Parse(
			ctx,
			request,
		)
		if err == nil {
			b.Fatal(
				"Parse() error = nil, want invalid signature",
			)
		}
	}
}

func BenchmarkParser_ParseMalformedToken(b *testing.B) {
	privateKey := testKeys(b)

	publicKey, err := key.ParsePublic(
		publicKeyPKIXPEM(
			b,
			privateKey,
		),
	)
	if err != nil {
		b.Fatalf(
			"ParsePublic() error = %v, want nil",
			err,
		)
	}

	parser, err := NewParser(
		key.NewStaticVerificationProvider(publicKey),
		AlgorithmRS256,
	)
	if err != nil {
		b.Fatalf(
			"NewParser() error = %v, want nil",
			err,
		)
	}

	request := token.ParseRequest{
		Value: "not.a.jwt",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := parser.Parse(
			ctx,
			request,
		)
		if err == nil {
			b.Fatal(
				"Parse() error = nil, want malformed token error",
			)
		}
	}
}

func BenchmarkParser_ParseOversizedToken(b *testing.B) {
	privateKey := testKeys(b)

	publicKey, err := key.ParsePublic(
		publicKeyPKIXPEM(
			b,
			privateKey,
		),
	)
	if err != nil {
		b.Fatalf(
			"ParsePublic() error = %v, want nil",
			err,
		)
	}

	parser, err := NewParser(
		key.NewStaticVerificationProvider(publicKey),
		AlgorithmRS256,
	)
	if err != nil {
		b.Fatalf(
			"NewParser() error = %v, want nil",
			err,
		)
	}

	value := token.Value(
		make(
			[]byte,
			maxTokenLength+1,
		),
	)

	request := token.ParseRequest{
		Value: value,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := parser.Parse(
			ctx,
			request,
		)
		if err == nil {
			b.Fatal(
				"Parse() error = nil, want oversized token error",
			)
		}
	}
}

func BenchmarkParser_ParseValidRS256Parallel(b *testing.B) {
	privateKey := testKeys(b)

	publicKey, err := key.ParsePublic(
		publicKeyPKIXPEM(
			b,
			privateKey,
		),
	)
	if err != nil {
		b.Fatalf(
			"ParsePublic() error = %v, want nil",
			err,
		)
	}

	parser, err := NewParser(
		key.NewStaticVerificationProvider(publicKey),
		AlgorithmRS256,
	)
	if err != nil {
		b.Fatalf(
			"NewParser() error = %v, want nil",
			err,
		)
	}

	value := token.Value(
		signValidToken(
			b,
			privateKey,
			"camera-front",
		),
	)

	request := token.ParseRequest{
		Value: value,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.SetBytes(
		int64(
			len(value),
		),
	)
	b.ResetTimer()

	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				parsed, err := parser.Parse(
					ctx,
					request,
				)
				if err != nil {
					b.Fatalf(
						"Parse() error = %v, want nil",
						err,
					)
				}

				if parsed.Claims.Subject != "camera-front" {
					b.Fatalf(
						"subject = %q, want %q",
						parsed.Claims.Subject,
						"camera-front",
					)
				}
			}
		},
	)
}
