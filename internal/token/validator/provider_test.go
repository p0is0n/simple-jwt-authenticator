package validator

import (
	"context"
	"errors"
	"testing"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

type recordingValidator struct {
	name    string
	order   *[]string
	calls   int
	request Request
	ctx     context.Context
	err     error
}

func (v *recordingValidator) Validate(
	ctx context.Context,
	request Request,
) error {
	v.calls++
	v.ctx = ctx
	v.request = request

	if v.order != nil {
		*v.order = append(*v.order, v.name)
	}

	return v.err
}

func TestProvider_PreservesConfiguredOrder(t *testing.T) {
	var order []string

	first := &recordingValidator{
		name:  "first",
		order: &order,
	}
	second := &recordingValidator{
		name:  "second",
		order: &order,
	}
	third := &recordingValidator{
		name:  "third",
		order: &order,
	}

	provider := NewProvider(
		first,
		second,
		third,
	)

	err := provider.Validate(
		context.Background(),
		Request{},
	)
	if err != nil {
		t.Fatalf(
			"Validate() error = %v, want nil",
			err,
		)
	}

	want := []string{
		"first",
		"second",
		"third",
	}

	if len(order) != len(want) {
		t.Fatalf(
			"validation order length = %d, want %d; order = %v",
			len(order),
			len(want),
			order,
		)
	}

	for index := range want {
		if order[index] != want[index] {
			t.Fatalf(
				"validation order[%d] = %q, want %q; order = %v",
				index,
				order[index],
				want[index],
				order,
			)
		}
	}
}

func TestProvider_StopsAfterFirstFailure(t *testing.T) {
	first := &recordingValidator{
		err: ErrExpired,
	}
	second := &recordingValidator{}

	provider := NewProvider(
		first,
		second,
	)

	err := provider.Validate(
		context.Background(),
		Request{},
	)

	if !errors.Is(
		err,
		ErrExpired,
	) {
		t.Fatalf(
			"Validate() error = %v, want ErrExpired",
			err,
		)
	}

	if first.calls != 1 {
		t.Fatalf(
			"first validator calls = %d, want 1",
			first.calls,
		)
	}

	if second.calls != 0 {
		t.Fatalf(
			"second validator calls = %d, want 0",
			second.calls,
		)
	}
}

func TestProvider_StopsAfterMiddleFailure(t *testing.T) {
	first := &recordingValidator{}
	second := &recordingValidator{
		err: ErrInvalidIssuer,
	}
	third := &recordingValidator{}

	provider := NewProvider(
		first,
		second,
		third,
	)

	err := provider.Validate(
		context.Background(),
		Request{},
	)

	if !errors.Is(
		err,
		ErrInvalidIssuer,
	) {
		t.Fatalf(
			"Validate() error = %v, want ErrInvalidIssuer",
			err,
		)
	}

	if first.calls != 1 {
		t.Fatalf(
			"first validator calls = %d, want 1",
			first.calls,
		)
	}

	if second.calls != 1 {
		t.Fatalf(
			"second validator calls = %d, want 1",
			second.calls,
		)
	}

	if third.calls != 0 {
		t.Fatalf(
			"third validator calls = %d, want 0",
			third.calls,
		)
	}
}

func TestProvider_PassesRequestToValidator(t *testing.T) {
	validation := &recordingValidator{}
	provider := NewProvider(validation)

	expression, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatalf(
			"NewMatch() error = %v, want nil",
			err,
		)
	}

	request := Request{
		Token: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
		ClaimExpression: expression,
	}

	err = provider.Validate(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatalf(
			"Validate() error = %v, want nil",
			err,
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"validator calls = %d, want 1",
			validation.calls,
		)
	}

	if got := validation.request.Token.Claims.Subject; got != "camera-front" {
		t.Fatalf(
			"validated subject = %q, want %q",
			got,
			"camera-front",
		)
	}

	if validation.request.ClaimExpression != expression {
		t.Fatal(
			"validator received a different claim expression",
		)
	}
}

func TestProvider_PropagatesContext(t *testing.T) {
	type contextKey string

	const key contextKey = "validator-test"

	ctx := context.WithValue(
		context.Background(),
		key,
		"value",
	)

	validation := &recordingValidator{}
	provider := NewProvider(validation)

	err := provider.Validate(
		ctx,
		Request{},
	)
	if err != nil {
		t.Fatalf(
			"Validate() error = %v, want nil",
			err,
		)
	}

	if got := validation.ctx.Value(key); got != "value" {
		t.Fatalf(
			"context value = %v, want %q",
			got,
			"value",
		)
	}
}

func TestProvider_NilClaimExpressionAddsNoPolicy(t *testing.T) {
	validation := &recordingValidator{}
	provider := NewProvider(validation)

	err := provider.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Subject: "camera-front",
				},
			},
		},
	)
	if err != nil {
		t.Fatalf(
			"Validate() error = %v, want nil",
			err,
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"validator calls = %d, want 1",
			validation.calls,
		)
	}
}

func TestProvider_AcceptsSatisfiedClaimExpression(t *testing.T) {
	expression, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatalf(
			"NewMatch() error = %v, want nil",
			err,
		)
	}

	validation := &recordingValidator{}
	provider := NewProvider(validation)

	err = provider.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Subject: "camera-front",
				},
			},
			ClaimExpression: expression,
		},
	)
	if err != nil {
		t.Fatalf(
			"Validate() error = %v, want nil",
			err,
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"validator calls = %d, want 1",
			validation.calls,
		)
	}
}

func TestProvider_RejectsUnsatisfiedClaimExpression(t *testing.T) {
	expression, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatalf(
			"NewMatch() error = %v, want nil",
			err,
		)
	}

	validation := &recordingValidator{}
	provider := NewProvider(validation)

	err = provider.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Subject: "camera-back",
				},
			},
			ClaimExpression: expression,
		},
	)

	if !errors.Is(
		err,
		ErrClaimExpressionNotSatisfied,
	) {
		t.Fatalf(
			"Validate() error = %v, want ErrClaimExpressionNotSatisfied",
			err,
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"validator calls = %d, want 1",
			validation.calls,
		)
	}
}

func TestProvider_DoesNotEvaluateClaimExpressionAfterValidationFailure(
	t *testing.T,
) {
	expression, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatalf(
			"NewMatch() error = %v, want nil",
			err,
		)
	}

	validation := &recordingValidator{
		err: ErrExpired,
	}

	provider := NewProvider(validation)

	err = provider.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Subject: "camera-back",
				},
			},
			ClaimExpression: expression,
		},
	)

	if !errors.Is(
		err,
		ErrExpired,
	) {
		t.Fatalf(
			"Validate() error = %v, want ErrExpired",
			err,
		)
	}

	if errors.Is(
		err,
		ErrClaimExpressionNotSatisfied,
	) {
		t.Fatal(
			"claim expression failure must not replace configured validation failure",
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"validator calls = %d, want 1",
			validation.calls,
		)
	}
}

func TestProvider_EvaluatesLogicalClaimExpression(t *testing.T) {
	front, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatal(err)
	}

	back, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-back",
	)
	if err != nil {
		t.Fatal(err)
	}

	camera, err := claim.NewAny(
		front,
		back,
	)
	if err != nil {
		t.Fatal(err)
	}

	audience, err := claim.NewMatch(
		claim.NameAudience,
		claim.OperatorRegex,
		`^frigate(?:-.+)?$`,
	)
	if err != nil {
		t.Fatal(err)
	}

	expression, err := claim.NewAll(
		camera,
		audience,
	)
	if err != nil {
		t.Fatal(err)
	}

	provider := NewProvider(
		&recordingValidator{},
	)

	err = provider.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Subject: "camera-back",
					Audience: []string{
						"home-assistant",
						"frigate-camera",
					},
				},
			},
			ClaimExpression: expression,
		},
	)
	if err != nil {
		t.Fatalf(
			"Validate() error = %v, want nil",
			err,
		)
	}
}

func TestProvider_EmptyProviderFailsClosed(t *testing.T) {
	provider := NewProvider()

	err := provider.Validate(
		context.Background(),
		Request{},
	)

	if !errors.Is(
		err,
		ErrNoValidators,
	) {
		t.Fatalf(
			"Validate() error = %v, want ErrNoValidators",
			err,
		)
	}
}

func TestProvider_EmptyProviderFailsClosedWithClaimExpression(t *testing.T) {
	expression, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-front",
	)
	if err != nil {
		t.Fatalf(
			"NewMatch() error = %v, want nil",
			err,
		)
	}

	provider := NewProvider()

	err = provider.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Subject: "camera-front",
				},
			},
			ClaimExpression: expression,
		},
	)

	if !errors.Is(
		err,
		ErrNoValidators,
	) {
		t.Fatalf(
			"Validate() error = %v, want ErrNoValidators",
			err,
		)
	}
}
