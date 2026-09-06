package validator

import (
	"context"
	"testing"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

func BenchmarkProvider_OneValidator(b *testing.B) {
	provider := NewProvider(
		Func(
			func(
				_ context.Context,
				_ Request,
			) error {
				return nil
			},
		),
	)

	request := Request{
		Token: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := provider.Validate(
			ctx,
			request,
		); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProvider_SixValidators(b *testing.B) {
	validation := Func(
		func(
			_ context.Context,
			_ Request,
		) error {
			return nil
		},
	)

	provider := NewProvider(
		validation,
		validation,
		validation,
		validation,
		validation,
		validation,
	)

	request := Request{
		Token: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := provider.Validate(
			ctx,
			request,
		); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProvider_SixValidatorsWithExpression(b *testing.B) {
	expression, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	validation := Func(
		func(
			_ context.Context,
			_ Request,
		) error {
			return nil
		},
	)

	provider := NewProvider(
		validation,
		validation,
		validation,
		validation,
		validation,
		validation,
	)

	request := Request{
		Token: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
		ClaimExpression: expression,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := provider.Validate(
			ctx,
			request,
		); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProvider_SixValidatorsWithNestedExpression(b *testing.B) {
	subjectFront, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	subjectBack, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-back",
	)
	if err != nil {
		b.Fatal(err)
	}

	subject, err := claim.NewAny(
		subjectFront,
		subjectBack,
	)
	if err != nil {
		b.Fatal(err)
	}

	audience, err := claim.NewMatch(
		claim.NameAudience,
		claim.OperatorEqual,
		"frigate",
	)
	if err != nil {
		b.Fatal(err)
	}

	username, err := claim.NewMatch(
		claim.NameUsername,
		claim.OperatorRegex,
		"^service-",
	)
	if err != nil {
		b.Fatal(err)
	}

	expression, err := claim.NewAll(
		subject,
		audience,
		username,
	)
	if err != nil {
		b.Fatal(err)
	}

	validation := Func(
		func(
			_ context.Context,
			_ Request,
		) error {
			return nil
		},
	)

	provider := NewProvider(
		validation,
		validation,
		validation,
		validation,
		validation,
		validation,
	)

	request := Request{
		Token: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
				Audience: []string{
					"frigate",
				},
				Username: "service-camera",
			},
		},
		ClaimExpression: expression,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := provider.Validate(
			ctx,
			request,
		); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProvider_Parallel(b *testing.B) {
	validation := Func(
		func(
			_ context.Context,
			_ Request,
		) error {
			return nil
		},
	)

	provider := NewProvider(
		validation,
		validation,
		validation,
		validation,
		validation,
		validation,
	)

	request := Request{
		Token: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				if err := provider.Validate(
					ctx,
					request,
				); err != nil {
					b.Fatal(err)
				}
			}
		},
	)
}
