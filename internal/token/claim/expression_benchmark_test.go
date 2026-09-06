package claim

import (
	"testing"
)

func BenchmarkExpression_Equal_Match(b *testing.B) {
	expression, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject: "camera-front",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkExpression_Equal_Mismatch(b *testing.B) {
	expression, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject: "camera-back",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to true")
		}
	}
}

func BenchmarkExpression_Regex_Match(b *testing.B) {
	expression, err := NewMatch(
		NameSubject,
		OperatorRegex,
		"^camera-[a-z]+$",
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject: "camera-front",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkExpression_Regex_Mismatch(b *testing.B) {
	expression, err := NewMatch(
		NameSubject,
		OperatorRegex,
		"^camera-[a-z]+$",
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject: "service-front",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to true")
		}
	}
}

func BenchmarkExpression_Audience_FirstMatch(b *testing.B) {
	expression, err := NewMatch(
		NameAudience,
		OperatorEqual,
		"frigate",
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Audience: []string{
			"frigate",
			"home-assistant",
			"grafana",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkExpression_Audience_LastMatch(b *testing.B) {
	expression, err := NewMatch(
		NameAudience,
		OperatorEqual,
		"frigate",
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Audience: []string{
			"home-assistant",
			"grafana",
			"prometheus",
			"loki",
			"frigate",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkExpression_Audience_NoMatch(b *testing.B) {
	expression, err := NewMatch(
		NameAudience,
		OperatorEqual,
		"frigate",
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Audience: []string{
			"home-assistant",
			"grafana",
			"prometheus",
			"loki",
			"tempo",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to true")
		}
	}
}

func BenchmarkExpression_All_EarlyFailure(b *testing.B) {
	subject, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	audience, err := NewMatch(
		NameAudience,
		OperatorEqual,
		"frigate",
	)
	if err != nil {
		b.Fatal(err)
	}

	username, err := NewMatch(
		NameUsername,
		OperatorRegex,
		"^service-",
	)
	if err != nil {
		b.Fatal(err)
	}

	expression, err := NewAll(
		subject,
		audience,
		username,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject:  "camera-back",
		Audience: []string{"frigate"},
		Username: "service-camera",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to true")
		}
	}
}

func BenchmarkExpression_All_FullEvaluation(b *testing.B) {
	subject, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	audience, err := NewMatch(
		NameAudience,
		OperatorEqual,
		"frigate",
	)
	if err != nil {
		b.Fatal(err)
	}

	username, err := NewMatch(
		NameUsername,
		OperatorRegex,
		"^service-",
	)
	if err != nil {
		b.Fatal(err)
	}

	expression, err := NewAll(
		subject,
		audience,
		username,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject:  "camera-front",
		Audience: []string{"frigate"},
		Username: "service-camera",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkExpression_Any_EarlySuccess(b *testing.B) {
	front, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	back, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-back",
	)
	if err != nil {
		b.Fatal(err)
	}

	regex, err := NewMatch(
		NameUsername,
		OperatorRegex,
		"^service-",
	)
	if err != nil {
		b.Fatal(err)
	}

	expression, err := NewAny(
		front,
		back,
		regex,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject:  "camera-front",
		Username: "service-camera",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkExpression_Any_LastSuccess(b *testing.B) {
	front, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	back, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-back",
	)
	if err != nil {
		b.Fatal(err)
	}

	regex, err := NewMatch(
		NameUsername,
		OperatorRegex,
		"^service-",
	)
	if err != nil {
		b.Fatal(err)
	}

	expression, err := NewAny(
		front,
		back,
		regex,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject:  "camera-garage",
		Username: "service-camera",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !Evaluate(
			expression,
			claims,
		) {
			b.Fatal("expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkExpression_EvaluateNil(b *testing.B) {
	claims := Claims{
		Subject: "camera-front",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !Evaluate(
			nil,
			claims,
		) {
			b.Fatal("nil expression unexpectedly evaluated to false")
		}
	}
}

func BenchmarkExpression_Parallel(b *testing.B) {
	subject, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		b.Fatal(err)
	}

	username, err := NewMatch(
		NameUsername,
		OperatorRegex,
		"^service-[a-z0-9-]+$",
	)
	if err != nil {
		b.Fatal(err)
	}

	expression, err := NewAll(
		subject,
		username,
	)
	if err != nil {
		b.Fatal(err)
	}

	claims := Claims{
		Subject:  "camera-front",
		Username: "service-camera-front",
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				if !Evaluate(
					expression,
					claims,
				) {
					b.Fatal(
						"expression unexpectedly evaluated to false",
					)
				}
			}
		},
	)
}
