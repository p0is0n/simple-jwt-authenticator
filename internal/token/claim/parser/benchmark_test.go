package parser

import (
	"testing"

	"simple-jwt-authenticator/internal/token/claim"
)

func BenchmarkParse_SimpleEquality(b *testing.B) {
	const expression = `subject == "camera-front"`

	b.ReportAllocs()

	for b.Loop() {
		parsed, err := Parse(expression)
		if err != nil {
			b.Fatal(err)
		}

		if parsed == nil {
			b.Fatal("Parse() returned nil expression")
		}
	}
}

func BenchmarkParse_SimpleRegex(b *testing.B) {
	const expression = `subject ~= "^camera-[a-z]+$"`

	b.ReportAllocs()

	for b.Loop() {
		parsed, err := Parse(expression)
		if err != nil {
			b.Fatal(err)
		}

		if parsed == nil {
			b.Fatal("Parse() returned nil expression")
		}
	}
}

func BenchmarkParse_And(b *testing.B) {
	const expression = `
		subject == "camera-front" &&
		audience == "frigate" &&
		issuer == "home-auth"
	`

	b.ReportAllocs()

	for b.Loop() {
		parsed, err := Parse(expression)
		if err != nil {
			b.Fatal(err)
		}

		if parsed == nil {
			b.Fatal("Parse() returned nil expression")
		}
	}
}

func BenchmarkParse_Nested(b *testing.B) {
	const expression = `
		(
			subject == "camera-front" ||
			subject == "camera-back"
		) &&
		audience == "frigate" &&
		(
			email == "admin@example.com" ||
			username ~= "^service-[a-z0-9-]+$"
		)
	`

	b.ReportAllocs()

	for b.Loop() {
		parsed, err := Parse(expression)
		if err != nil {
			b.Fatal(err)
		}

		if parsed == nil {
			b.Fatal("Parse() returned nil expression")
		}
	}
}

func BenchmarkEvaluate_SimpleEquality(b *testing.B) {
	expression, err := Parse(
		`subject == "camera-front"`,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := claim.Claims{
		Subject: "camera-front",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !claim.Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkEvaluate_SimpleRegex(b *testing.B) {
	expression, err := Parse(
		`subject ~= "^camera-[a-z]+$"`,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := claim.Claims{
		Subject: "camera-front",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !claim.Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkEvaluate_NestedFirstOrBranchMatches(b *testing.B) {
	expression, err := Parse(
		`
		(
			subject == "camera-front" ||
			subject == "camera-back"
		) &&
		audience == "frigate" &&
		(
			email == "admin@example.com" ||
			username ~= "^service-[a-z0-9-]+$"
		)
		`,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := claim.Claims{
		Subject: "camera-front",
		Audience: []string{
			"frigate",
		},
		Email: "admin@example.com",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !claim.Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkEvaluate_NestedSecondOrBranchMatches(b *testing.B) {
	expression, err := Parse(
		`
		(
			subject == "camera-front" ||
			subject == "camera-back"
		) &&
		audience == "frigate" &&
		(
			email == "admin@example.com" ||
			username ~= "^service-[a-z0-9-]+$"
		)
		`,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := claim.Claims{
		Subject: "camera-back",
		Audience: []string{
			"home-assistant",
			"frigate",
		},
		Username: "service-camera-front",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !claim.Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkParseAndEvaluate_Nested(b *testing.B) {
	const policy = `
		(
			subject == "camera-front" ||
			subject == "camera-back"
		) &&
		audience == "frigate" &&
		username ~= "^service-[a-z0-9-]+$"
	`

	claims := claim.Claims{
		Subject: "camera-front",
		Audience: []string{
			"frigate",
		},
		Username: "service-camera-front",
	}

	b.ReportAllocs()

	for b.Loop() {
		expression, err := Parse(policy)
		if err != nil {
			b.Fatal(err)
		}

		if !claim.Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}
