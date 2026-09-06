package parser

import (
	"errors"
	"strings"
	"testing"

	"simple-jwt-authenticator/internal/token/claim"
)

func TestParse_ExactSubjectMatch(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "camera-front"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-back",
		},
		false,
	)
}

func TestParse_EqualityIsCaseSensitive(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "Camera-Front"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
		},
		false,
	)
}

func TestParse_RegexMatch(t *testing.T) {
	expression := mustParse(
		t,
		`subject ~= "^camera-[a-z]+$"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "user-front",
		},
		false,
	)
}

func TestParse_RegexUsesSearchSemantics(t *testing.T) {
	expression := mustParse(
		t,
		`subject ~= "admin"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "super-admin-user",
		},
		true,
	)
}

func TestParse_AnchoredRegexUsesFullMatchWhenRequested(t *testing.T) {
	expression := mustParse(
		t,
		`subject ~= "^admin$"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "admin",
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "super-admin",
		},
		false,
	)
}

func TestParse_MissingScalarDoesNotMatchEquality(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "camera-front"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{},
		false,
	)
}

func TestParse_MissingScalarDoesNotMatchRegex(t *testing.T) {
	expression := mustParse(
		t,
		`subject ~= "^.*$"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{},
		false,
	)
}

func TestParse_AllSupportedScalarClaims(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		claims     claim.Claims
	}{
		{
			name:       "subject",
			expression: `subject == "camera-front"`,
			claims: claim.Claims{
				Subject: "camera-front",
			},
		},
		{
			name:       "issuer",
			expression: `issuer == "home-auth"`,
			claims: claim.Claims{
				Issuer: "home-auth",
			},
		},
		{
			name:       "id",
			expression: `id == "token-id"`,
			claims: claim.Claims{
				ID: "token-id",
			},
		},
		{
			name:       "username",
			expression: `username == "front-camera"`,
			claims: claim.Claims{
				Username: "front-camera",
			},
		},
		{
			name:       "email",
			expression: `email == "camera@example.com"`,
			claims: claim.Claims{
				Email: "camera@example.com",
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				expression := mustParse(
					t,
					test.expression,
				)

				assertEvaluation(
					t,
					expression,
					test.claims,
					true,
				)
			},
		)
	}
}

func TestParse_AudienceMatchesAnyElement(t *testing.T) {
	expression := mustParse(
		t,
		`audience == "frigate"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Audience: []string{
				"home-assistant",
				"frigate",
				"grafana",
			},
		},
		true,
	)
}

func TestParse_AudienceRejectsWhenNoElementMatches(t *testing.T) {
	expression := mustParse(
		t,
		`audience == "frigate"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Audience: []string{
				"home-assistant",
				"grafana",
			},
		},
		false,
	)
}

func TestParse_AudienceRegexMatchesAnyElement(t *testing.T) {
	expression := mustParse(
		t,
		`audience ~= "^frigate-"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Audience: []string{
				"home-assistant",
				"frigate-camera",
			},
		},
		true,
	)
}

func TestParse_AndRequiresAllExpressions(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "camera-front" && audience == "frigate"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
			Audience: []string{
				"frigate",
			},
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
			Audience: []string{
				"grafana",
			},
		},
		false,
	)
}

func TestParse_OrRequiresAnyExpression(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "camera-front" || subject == "camera-back"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-back",
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-garage",
		},
		false,
	)
}

func TestParse_AndHasHigherPrecedenceThanOr(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "front" || subject == "back" && audience == "frigate"`,
	)

	// Equivalent to:
	//
	// subject == "front"
	// ||
	// (
	//     subject == "back"
	//     &&
	//     audience == "frigate"
	// )

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "front",
			Audience: []string{
				"other",
			},
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "back",
			Audience: []string{
				"frigate",
			},
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "back",
			Audience: []string{
				"other",
			},
		},
		false,
	)
}

func TestParse_ParenthesesOverridePrecedence(t *testing.T) {
	expression := mustParse(
		t,
		`(subject == "front" || subject == "back") && audience == "frigate"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "front",
			Audience: []string{
				"other",
			},
		},
		false,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "front",
			Audience: []string{
				"frigate",
			},
		},
		true,
	)
}

func TestParse_NestedLogicalExpression(t *testing.T) {
	expression := mustParse(
		t,
		`(
			(subject == "camera-front" || subject == "camera-back") &&
			audience == "frigate"
		) && (
			email == "admin@example.com" ||
			username ~= "^service-"
		)`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
			Audience: []string{
				"frigate",
			},
			Username: "service-camera",
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
			Audience: []string{
				"frigate",
			},
			Email: "admin@example.com",
		},
		true,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
			Audience: []string{
				"frigate",
			},
			Email:    "user@example.com",
			Username: "ordinary-user",
		},
		false,
	)
}

func TestParse_MultipleAndExpressions(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "camera-front" &&
		 issuer == "home-auth" &&
		 audience == "frigate" &&
		 username == "camera"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject:  "camera-front",
			Issuer:   "home-auth",
			Audience: []string{"frigate"},
			Username: "camera",
		},
		true,
	)
}

func TestParse_MultipleOrExpressions(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "front" ||
		 subject == "back" ||
		 subject == "garage"`,
	)

	for _, subject := range []string{
		"front",
		"back",
		"garage",
	} {
		assertEvaluation(
			t,
			expression,
			claim.Claims{
				Subject: subject,
			},
			true,
		)
	}

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "unknown",
		},
		false,
	)
}

func TestParse_RedundantParenthesesAreAllowed(t *testing.T) {
	expression := mustParse(
		t,
		`(((subject == "camera-front")))`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
		},
		true,
	)
}

func TestParse_WhitespaceIsInsignificant(t *testing.T) {
	expression := mustParse(
		t,
		" \n\t( subject\t==\n\"front\" ||\nsubject == \"back\" )\r\n&& audience == \"frigate\" ",
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "front",
			Audience: []string{
				"frigate",
			},
		},
		true,
	)
}

func TestParse_DecodesEscapedQuote(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "camera-\"front\""`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: `camera-"front"`,
		},
		true,
	)
}

func TestParse_DecodesEscapedBackslashForRegex(t *testing.T) {
	expression := mustParse(
		t,
		`subject ~= "^camera\\.[0-9]+$"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera.42",
		},
		true,
	)
}

func TestParse_UnicodeString(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "камера-передняя"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "камера-передняя",
		},
		true,
	)
}

func TestParse_UnicodeEscape(t *testing.T) {
	expression := mustParse(
		t,
		`subject == "\u043a\u0430\u043c\u0435\u0440\u0430"`,
	)

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "камера",
		},
		true,
	)
}

func TestParse_RejectsEmptyInput(t *testing.T) {
	assertParseErrorIs(
		t,
		"",
		ErrSyntax,
	)
}

func TestParse_RejectsWhitespaceOnly(t *testing.T) {
	assertParseErrorIs(
		t,
		" \n\t\r ",
		ErrSyntax,
	)
}

func TestParse_RejectsUnknownClaim(t *testing.T) {
	assertParseErrorIs(
		t,
		`role == "admin"`,
		claim.ErrInvalidName,
	)
}

func TestParse_RejectsEmptyValue(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == ""`,
		claim.ErrEmptyMatchValue,
	)
}

func TestParse_RejectsInvalidRegex(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject ~= "["`,
		claim.ErrInvalidRegex,
	)
}

func TestParse_RejectsMissingOperator(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject "camera"`,
		ErrSyntax,
	)
}

func TestParse_RejectsSingleEqualOperator(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject = "camera"`,
		ErrSyntax,
	)
}

func TestParse_RejectsUnsupportedNotEqualOperator(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject != "camera"`,
		ErrSyntax,
	)
}

func TestParse_RejectsUnsupportedRegexNegation(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject !~ "camera"`,
		ErrSyntax,
	)
}

func TestParse_RejectsBareComparisonValue(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == camera-front`,
		ErrSyntax,
	)
}

func TestParse_RejectsNumberComparisonValue(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == 123`,
		ErrSyntax,
	)
}

func TestParse_RejectsMissingComparisonValue(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject ==`,
		ErrSyntax,
	)
}

func TestParse_RejectsLeadingAnd(t *testing.T) {
	assertParseErrorIs(
		t,
		`&& subject == "camera"`,
		ErrSyntax,
	)
}

func TestParse_RejectsTrailingAnd(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "camera" &&`,
		ErrSyntax,
	)
}

func TestParse_RejectsLeadingOr(t *testing.T) {
	assertParseErrorIs(
		t,
		`|| subject == "camera"`,
		ErrSyntax,
	)
}

func TestParse_RejectsTrailingOr(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "camera" ||`,
		ErrSyntax,
	)
}

func TestParse_RejectsRepeatedAnd(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "a" && && audience == "b"`,
		ErrSyntax,
	)
}

func TestParse_RejectsRepeatedOr(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "a" || || audience == "b"`,
		ErrSyntax,
	)
}

func TestParse_RejectsMixedBrokenLogicalOperator(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "a" && || audience == "b"`,
		ErrSyntax,
	)
}

func TestParse_RejectsEmptyParentheses(t *testing.T) {
	assertParseErrorIs(
		t,
		`()`,
		ErrSyntax,
	)
}

func TestParse_RejectsMissingClosingParenthesis(t *testing.T) {
	assertParseErrorIs(
		t,
		`(subject == "camera"`,
		ErrSyntax,
	)
}

func TestParse_RejectsUnexpectedClosingParenthesis(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "camera")`,
		ErrSyntax,
	)
}

func TestParse_RejectsExtraClosingParenthesis(t *testing.T) {
	assertParseErrorIs(
		t,
		`((subject == "camera")))`,
		ErrSyntax,
	)
}

func TestParse_RejectsAdjacentExpressionsWithoutOperator(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "front" audience == "frigate"`,
		ErrSyntax,
	)
}

func TestParse_RejectsAdjacentParenthesizedExpressions(t *testing.T) {
	assertParseErrorIs(
		t,
		`(subject == "front")(audience == "frigate")`,
		ErrSyntax,
	)
}

func TestParse_RejectsUnexpectedTrailingInput(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "camera" garbage`,
		ErrSyntax,
	)
}

func TestParse_RejectsUnterminatedString(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "camera`,
		ErrSyntax,
	)
}

func TestParse_RejectsInvalidStringEscape(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "\q"`,
		ErrSyntax,
	)
}

func TestParse_RejectsRawNewlineInsideString(t *testing.T) {
	assertParseErrorIs(
		t,
		"subject == \"camera\nfront\"",
		ErrSyntax,
	)
}

func TestParse_RejectsUnexpectedCharacter(t *testing.T) {
	assertParseErrorIs(
		t,
		`subject == "camera" @ audience == "frigate"`,
		ErrSyntax,
	)
}

func TestParse_RejectsExpressionLargerThanMaximum(t *testing.T) {
	value := strings.Repeat(
		" ",
		maxExpressionBytes+1,
	)

	_, err := Parse(
		value,
	)

	if !errors.Is(
		err,
		ErrExpressionTooLarge,
	) {
		t.Fatalf(
			"Parse() error = %v, want ErrExpressionTooLarge",
			err,
		)
	}

	if errors.Is(
		err,
		ErrSyntax,
	) {
		t.Fatalf(
			"oversized expression must be classified as size failure, got %v",
			err,
		)
	}
}

func TestParse_AcceptsInputAtMaximumSize(t *testing.T) {
	base := `subject == "camera-front"`

	paddingSize := maxExpressionBytes - len(base)
	if paddingSize < 0 {
		t.Fatal(
			"test expression unexpectedly exceeds parser size limit",
		)
	}

	value := strings.Repeat(
		" ",
		paddingSize,
	) + base

	expression, err := Parse(
		value,
	)
	if err != nil {
		t.Fatalf(
			"Parse() error = %v, want nil",
			err,
		)
	}

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera-front",
		},
		true,
	)
}

func TestParse_RejectsParenthesisNestingBeyondMaximum(t *testing.T) {
	value := strings.Repeat(
		"(",
		maxParenthesisDepth+1,
	) +
		`subject == "camera"` +
		strings.Repeat(
			")",
			maxParenthesisDepth+1,
		)

	_, err := Parse(
		value,
	)

	if !errors.Is(
		err,
		claim.ErrExpressionTooComplex,
	) {
		t.Fatalf(
			"Parse() error = %v, want claim.ErrExpressionTooComplex",
			err,
		)
	}
}

func TestParse_AcceptsParenthesisNestingAtMaximum(t *testing.T) {
	value := strings.Repeat(
		"(",
		maxParenthesisDepth,
	) +
		`subject == "camera"` +
		strings.Repeat(
			")",
			maxParenthesisDepth,
		)

	expression, err := Parse(
		value,
	)
	if err != nil {
		t.Fatalf(
			"Parse() error = %v, want nil",
			err,
		)
	}

	assertEvaluation(
		t,
		expression,
		claim.Claims{
			Subject: "camera",
		},
		true,
	)
}

func TestParse_PropagatesMatchValueComplexityError(t *testing.T) {
	value := strings.Repeat(
		"a",
		1025,
	)

	_, err := Parse(
		`subject == "` + value + `"`,
	)

	if !errors.Is(
		err,
		claim.ErrExpressionTooComplex,
	) {
		t.Fatalf(
			"Parse() error = %v, want claim.ErrExpressionTooComplex",
			err,
		)
	}
}

func TestParse_PropagatesLogicalNodeComplexityError(t *testing.T) {
	const comparisons = 65

	var builder strings.Builder

	for index := 0; index < comparisons; index++ {
		if index > 0 {
			builder.WriteString(
				" && ",
			)
		}

		builder.WriteString(
			`subject == "camera"`,
		)
	}

	_, err := Parse(
		builder.String(),
	)

	if !errors.Is(
		err,
		claim.ErrExpressionTooComplex,
	) {
		t.Fatalf(
			"Parse() error = %v, want claim.ErrExpressionTooComplex",
			err,
		)
	}
}

func TestParse_DoesNotTreatUnknownClaimAsSyntaxError(t *testing.T) {
	_, err := Parse(
		`unknown == "value"`,
	)

	if !errors.Is(
		err,
		claim.ErrInvalidName,
	) {
		t.Fatalf(
			"Parse() error = %v, want claim.ErrInvalidName",
			err,
		)
	}

	if errors.Is(
		err,
		ErrSyntax,
	) {
		t.Fatalf(
			"semantic claim error must not be classified as syntax error: %v",
			err,
		)
	}
}

func TestParse_DoesNotTreatInvalidRegexAsSyntaxError(t *testing.T) {
	_, err := Parse(
		`subject ~= "["`,
	)

	if !errors.Is(
		err,
		claim.ErrInvalidRegex,
	) {
		t.Fatalf(
			"Parse() error = %v, want claim.ErrInvalidRegex",
			err,
		)
	}

	if errors.Is(
		err,
		ErrSyntax,
	) {
		t.Fatalf(
			"regex validation error must not be classified as syntax error: %v",
			err,
		)
	}
}

func mustParse(
	t *testing.T,
	value string,
) claim.Expression {
	t.Helper()

	expression, err := Parse(
		value,
	)
	if err != nil {
		t.Fatalf(
			"Parse(%q) error = %v, want nil",
			value,
			err,
		)
	}

	if expression == nil {
		t.Fatalf(
			"Parse(%q) expression = nil, want non-nil",
			value,
		)
	}

	return expression
}

func assertParseErrorIs(
	t *testing.T,
	value string,
	target error,
) {
	t.Helper()

	expression, err := Parse(
		value,
	)

	if !errors.Is(
		err,
		target,
	) {
		t.Fatalf(
			"Parse(%q) error = %v, want %v",
			value,
			err,
			target,
		)
	}

	if expression != nil {
		t.Fatalf(
			"Parse(%q) expression = %#v, want nil",
			value,
			expression,
		)
	}
}

func assertEvaluation(
	t *testing.T,
	expression claim.Expression,
	claims claim.Claims,
	want bool,
) {
	t.Helper()

	got := claim.Evaluate(
		expression,
		claims,
	)

	if got != want {
		t.Fatalf(
			"Evaluate() = %t, want %t for claims %+v",
			got,
			want,
			claims,
		)
	}
}
