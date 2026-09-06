package claim

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestMatchEqual(t *testing.T) {
	tests := []struct {
		name     string
		claim    Name
		expected string
		claims   Claims
		want     bool
	}{
		{
			name:     "subject matches",
			claim:    NameSubject,
			expected: "camera-front",
			claims: Claims{
				Subject: "camera-front",
			},
			want: true,
		},
		{
			name:     "subject differs",
			claim:    NameSubject,
			expected: "camera-front",
			claims: Claims{
				Subject: "camera-back",
			},
		},
		{
			name:     "missing subject does not match",
			claim:    NameSubject,
			expected: "camera-front",
			claims:   Claims{},
		},
		{
			name:     "username matches",
			claim:    NameUsername,
			expected: "front",
			claims: Claims{
				Username: "front",
			},
			want: true,
		},
		{
			name:     "email matches",
			claim:    NameEmail,
			expected: "front@example.com",
			claims: Claims{
				Email: "front@example.com",
			},
			want: true,
		},
		{
			name:     "issuer matches",
			claim:    NameIssuer,
			expected: "home-auth",
			claims: Claims{
				Issuer: "home-auth",
			},
			want: true,
		},
		{
			name:     "id matches",
			claim:    NameID,
			expected: "token-id",
			claims: Claims{
				ID: "token-id",
			},
			want: true,
		},
		{
			name:     "audience matches one value",
			claim:    NameAudience,
			expected: "frigate",
			claims: Claims{
				Audience: []string{
					"home-assistant",
					"frigate",
				},
			},
			want: true,
		},
		{
			name:     "audience does not match",
			claim:    NameAudience,
			expected: "frigate",
			claims: Claims{
				Audience: []string{
					"home-assistant",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				expression, err := NewMatch(
					test.claim,
					OperatorEqual,
					test.expected,
				)
				if err != nil {
					t.Fatalf(
						"NewMatch() error = %v, want nil",
						err,
					)
				}

				got := Evaluate(
					expression,
					test.claims,
				)

				if got != test.want {
					t.Fatalf(
						"Evaluate() = %v, want %v",
						got,
						test.want,
					)
				}
			},
		)
	}
}

func TestMatchRegex(t *testing.T) {
	tests := []struct {
		name    string
		claim   Name
		pattern string
		claims  Claims
		want    bool
	}{
		{
			name:    "subject matches regex",
			claim:   NameSubject,
			pattern: `^camera-[a-z]+$`,
			claims: Claims{
				Subject: "camera-front",
			},
			want: true,
		},
		{
			name:    "subject does not match regex",
			claim:   NameSubject,
			pattern: `^camera-[a-z]+$`,
			claims: Claims{
				Subject: "sensor-front",
			},
		},
		{
			name:    "missing claim does not match regex accepting empty",
			claim:   NameUsername,
			pattern: `^.*$`,
			claims:  Claims{},
		},
		{
			name:    "audience matches regex",
			claim:   NameAudience,
			pattern: `^frigate(?:-.+)?$`,
			claims: Claims{
				Audience: []string{
					"home-assistant",
					"frigate-camera",
				},
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				expression, err := NewMatch(
					test.claim,
					OperatorRegex,
					test.pattern,
				)
				if err != nil {
					t.Fatalf(
						"NewMatch() error = %v, want nil",
						err,
					)
				}

				got := Evaluate(
					expression,
					test.claims,
				)

				if got != test.want {
					t.Fatalf(
						"Evaluate() = %v, want %v",
						got,
						test.want,
					)
				}
			},
		)
	}
}

func TestAll(t *testing.T) {
	subject, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatalf(
			"create subject expression: %v",
			err,
		)
	}

	audience, err := NewMatch(
		NameAudience,
		OperatorEqual,
		"frigate",
	)
	if err != nil {
		t.Fatalf(
			"create audience expression: %v",
			err,
		)
	}

	expression, err := NewAll(
		subject,
		audience,
	)
	if err != nil {
		t.Fatalf(
			"NewAll() error = %v, want nil",
			err,
		)
	}

	if !Evaluate(
		expression,
		Claims{
			Subject: "camera-front",
			Audience: []string{
				"frigate",
			},
		},
	) {
		t.Fatal(
			"AND expression should match when all children match",
		)
	}

	if Evaluate(
		expression,
		Claims{
			Subject: "camera-front",
			Audience: []string{
				"home-assistant",
			},
		},
	) {
		t.Fatal(
			"AND expression must fail when one child does not match",
		)
	}
}

func TestAny(t *testing.T) {
	front, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatalf(
			"create front expression: %v",
			err,
		)
	}

	back, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-back",
	)
	if err != nil {
		t.Fatalf(
			"create back expression: %v",
			err,
		)
	}

	expression, err := NewAny(
		front,
		back,
	)
	if err != nil {
		t.Fatalf(
			"NewAny() error = %v, want nil",
			err,
		)
	}

	if !Evaluate(
		expression,
		Claims{
			Subject: "camera-back",
		},
	) {
		t.Fatal(
			"OR expression should match when one child matches",
		)
	}

	if Evaluate(
		expression,
		Claims{
			Subject: "camera-side",
		},
	) {
		t.Fatal(
			"OR expression must fail when no child matches",
		)
	}
}

func TestNestedExpression(t *testing.T) {
	front, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatal(err)
	}

	back, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-back",
	)
	if err != nil {
		t.Fatal(err)
	}

	camera, err := NewAny(
		front,
		back,
	)
	if err != nil {
		t.Fatal(err)
	}

	audience, err := NewMatch(
		NameAudience,
		OperatorRegex,
		`^frigate(?:-.+)?$`,
	)
	if err != nil {
		t.Fatal(err)
	}

	expression, err := NewAll(
		camera,
		audience,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !Evaluate(
		expression,
		Claims{
			Subject: "camera-back",
			Audience: []string{
				"frigate-camera",
			},
		},
	) {
		t.Fatal(
			"nested expression should match",
		)
	}

	if Evaluate(
		expression,
		Claims{
			Subject: "camera-side",
			Audience: []string{
				"frigate-camera",
			},
		},
	) {
		t.Fatal(
			"nested expression should reject unmatched subject",
		)
	}
}

func TestNewMatchRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		claim    Name
		operator Operator
		value    string
		wantErr  error
	}{
		{
			name:     "unsupported claim",
			claim:    Name("unknown"),
			operator: OperatorEqual,
			value:    "value",
			wantErr:  ErrInvalidName,
		},
		{
			name:     "unsupported operator",
			claim:    NameSubject,
			operator: Operator("unknown"),
			value:    "value",
			wantErr:  ErrInvalidOperator,
		},
		{
			name:     "empty value",
			claim:    NameSubject,
			operator: OperatorEqual,
			wantErr:  ErrEmptyMatchValue,
		},
		{
			name:     "invalid regex",
			claim:    NameSubject,
			operator: OperatorRegex,
			value:    "[",
			wantErr:  ErrInvalidRegex,
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				_, err := NewMatch(
					test.claim,
					test.operator,
					test.value,
				)

				if !errors.Is(
					err,
					test.wantErr,
				) {
					t.Fatalf(
						"NewMatch() error = %v, want %v",
						err,
						test.wantErr,
					)
				}
			},
		)
	}
}

func TestNewMatchRejectsExcessiveValue(t *testing.T) {
	_, err := NewMatch(
		NameSubject,
		OperatorEqual,
		strings.Repeat(
			"a",
			maxMatchValueBytes+1,
		),
	)

	if !errors.Is(
		err,
		ErrExpressionTooComplex,
	) {
		t.Fatalf(
			"NewMatch() error = %v, want %v",
			err,
			ErrExpressionTooComplex,
		)
	}
}

func TestLogicalExpressionRejectsInvalidInput(t *testing.T) {
	match, err := NewMatch(
		NameSubject,
		OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		builder func(...Expression) (Expression, error)
		values  []Expression
	}{
		{
			name:    "all empty",
			builder: NewAll,
		},
		{
			name:    "all single child",
			builder: NewAll,
			values: []Expression{
				match,
			},
		},
		{
			name:    "all nil child",
			builder: NewAll,
			values: []Expression{
				match,
				nil,
			},
		},
		{
			name:    "any empty",
			builder: NewAny,
		},
		{
			name:    "any single child",
			builder: NewAny,
			values: []Expression{
				match,
			},
		},
		{
			name:    "any nil child",
			builder: NewAny,
			values: []Expression{
				match,
				nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				_, err := test.builder(
					test.values...,
				)

				if !errors.Is(
					err,
					ErrInvalidExpression,
				) {
					t.Fatalf(
						"builder error = %v, want %v",
						err,
						ErrInvalidExpression,
					)
				}
			},
		)
	}
}

func TestExpressionNodeLimit(t *testing.T) {
	expressions := make(
		[]Expression,
		0,
		maxExpressionNodes,
	)

	for index := 0; index < maxExpressionNodes; index++ {
		expression, err := NewMatch(
			NameSubject,
			OperatorEqual,
			fmt.Sprintf(
				"camera-%d",
				index,
			),
		)
		if err != nil {
			t.Fatal(err)
		}

		expressions = append(
			expressions,
			expression,
		)
	}

	_, err := NewAny(
		expressions...,
	)

	if !errors.Is(
		err,
		ErrExpressionTooComplex,
	) {
		t.Fatalf(
			"NewAny() error = %v, want %v",
			err,
			ErrExpressionTooComplex,
		)
	}
}

func TestEvaluateNilExpressionSucceeds(t *testing.T) {
	if !Evaluate(
		nil,
		Claims{},
	) {
		t.Fatal(
			"nil expression should represent no additional policy",
		)
	}
}
