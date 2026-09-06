package authentication

import (
	"context"
	"testing"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
	"simple-jwt-authenticator/internal/token/validator"
)

type benchmarkParser struct {
	result token.Token
}

func (p benchmarkParser) Parse(
	_ context.Context,
	_ token.ParseRequest,
) (token.Token, error) {
	return p.result, nil
}

func BenchmarkAuthenticator_Success(b *testing.B) {
	parser := benchmarkParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject:  "camera-front",
				Username: "service-camera",
				Email:    "camera@example.com",
			},
		},
	}

	validation := validator.Func(
		func(
			_ context.Context,
			_ validator.Request,
		) error {
			return nil
		},
	)

	provider := validator.NewProvider(
		validation,
	)

	authenticator, err := NewAuthenticator(
		parser,
		provider,
	)
	if err != nil {
		b.Fatal(err)
	}

	request := Request{
		Credential: Credential{
			Value: token.Value(
				"benchmark-token",
			),
		},
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		identity, err := authenticator.Authenticate(
			ctx,
			request,
		)
		if err != nil {
			b.Fatal(err)
		}

		if identity.Subject != "camera-front" {
			b.Fatal(
				"unexpected identity subject",
			)
		}
	}
}

func BenchmarkAuthenticator_SuccessSixValidators(b *testing.B) {
	parser := benchmarkParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject:  "camera-front",
				Username: "service-camera",
				Email:    "camera@example.com",
			},
		},
	}

	validation := validator.Func(
		func(
			_ context.Context,
			_ validator.Request,
		) error {
			return nil
		},
	)

	provider := validator.NewProvider(
		validation,
		validation,
		validation,
		validation,
		validation,
		validation,
	)

	authenticator, err := NewAuthenticator(
		parser,
		provider,
	)
	if err != nil {
		b.Fatal(err)
	}

	request := Request{
		Credential: Credential{
			Value: token.Value(
				"benchmark-token",
			),
		},
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		identity, err := authenticator.Authenticate(
			ctx,
			request,
		)
		if err != nil {
			b.Fatal(err)
		}

		if identity.Subject != "camera-front" {
			b.Fatal(
				"unexpected identity subject",
			)
		}
	}
}

func BenchmarkAuthenticator_SuccessWithClaimExpression(b *testing.B) {
	expression, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	parser := benchmarkParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject:  "camera-front",
				Username: "service-camera",
				Email:    "camera@example.com",
			},
		},
	}

	validation := validator.Func(
		func(
			_ context.Context,
			_ validator.Request,
		) error {
			return nil
		},
	)

	provider := validator.NewProvider(
		validation,
		validation,
		validation,
		validation,
		validation,
		validation,
	)

	authenticator, err := NewAuthenticator(
		parser,
		provider,
	)
	if err != nil {
		b.Fatal(err)
	}

	request := Request{
		Credential: Credential{
			Value: token.Value(
				"benchmark-token",
			),
		},
		ClaimExpression: expression,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		identity, err := authenticator.Authenticate(
			ctx,
			request,
		)
		if err != nil {
			b.Fatal(err)
		}

		if identity.Subject != "camera-front" {
			b.Fatal(
				"unexpected identity subject",
			)
		}
	}
}

func BenchmarkAuthenticator_Parallel(b *testing.B) {
	parser := benchmarkParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject:  "camera-front",
				Username: "service-camera",
				Email:    "camera@example.com",
			},
		},
	}

	validation := validator.Func(
		func(
			_ context.Context,
			_ validator.Request,
		) error {
			return nil
		},
	)

	provider := validator.NewProvider(
		validation,
		validation,
		validation,
		validation,
		validation,
		validation,
	)

	authenticator, err := NewAuthenticator(
		parser,
		provider,
	)
	if err != nil {
		b.Fatal(err)
	}

	request := Request{
		Credential: Credential{
			Value: token.Value(
				"benchmark-token",
			),
		},
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				identity, err := authenticator.Authenticate(
					ctx,
					request,
				)
				if err != nil {
					b.Fatal(err)
				}

				if identity.Subject != "camera-front" {
					b.Fatal(
						"unexpected identity subject",
					)
				}
			}
		},
	)
}
