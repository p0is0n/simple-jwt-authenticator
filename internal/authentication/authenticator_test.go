package authentication

import (
	"context"
	"errors"
	"testing"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
	"simple-jwt-authenticator/internal/token/validator"
)

type contextKey string

const testContextKey contextKey = "authentication-test"

// fakeParser is a consumer-side fake for token.Parser.
type fakeParser struct {
	calls   int
	request token.ParseRequest
	ctx     context.Context
	result  token.Token
	err     error
}

func (p *fakeParser) Parse(
	ctx context.Context,
	request token.ParseRequest,
) (token.Token, error) {
	p.calls++
	p.ctx = ctx
	p.request = request

	return p.result, p.err
}

// recordingValidator records validation calls and can be configured to return
// an error.
type recordingValidator struct {
	calls   int
	request validator.Request
	ctx     context.Context
	err     error
}

func (v *recordingValidator) Validate(
	ctx context.Context,
	request validator.Request,
) error {
	v.calls++
	v.ctx = ctx
	v.request = request

	return v.err
}

func TestNewAuthenticator_RejectsNilParser(t *testing.T) {
	authenticator, err := NewAuthenticator(
		nil,
		validator.NewProvider(),
	)

	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf(
			"expected ErrInvalidConfiguration, got %v",
			err,
		)
	}

	if authenticator != nil {
		t.Fatalf(
			"expected nil authenticator, got %+v",
			authenticator,
		)
	}
}

func TestNewAuthenticator_RejectsNilValidatorProvider(t *testing.T) {
	parser := &fakeParser{}

	authenticator, err := NewAuthenticator(
		parser,
		nil,
	)

	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf(
			"expected ErrInvalidConfiguration, got %v",
			err,
		)
	}

	if authenticator != nil {
		t.Fatalf(
			"expected nil authenticator, got %+v",
			authenticator,
		)
	}
}

func TestAuthenticator_RejectsMissingCredential(t *testing.T) {
	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{},
	)

	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf(
			"expected ErrAuthentication, got %v",
			err,
		)
	}

	if !errors.Is(err, ErrMissingCredential) {
		t.Fatalf(
			"expected ErrMissingCredential, got %v",
			err,
		)
	}

	if parser.calls != 0 {
		t.Fatalf(
			"parser must not be called for missing credential: got %d calls",
			parser.calls,
		)
	}

	if validation.calls != 0 {
		t.Fatalf(
			"validator must not be called for missing credential: got %d calls",
			validation.calls,
		)
	}

	if identity != (Identity{}) {
		t.Fatalf(
			"expected empty identity, got %+v",
			identity,
		)
	}
}

func TestAuthenticator_ParsesCredentialExactlyOnce(t *testing.T) {
	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	_, err = authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "credential-value",
			},
		},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if parser.calls != 1 {
		t.Fatalf(
			"unexpected parser call count: got %d, want 1",
			parser.calls,
		)
	}

	if parser.request.Value != "credential-value" {
		t.Fatalf(
			"unexpected parser value: got %q, want %q",
			parser.request.Value,
			"credential-value",
		)
	}
}

func TestAuthenticator_PassesParsedTokenToValidator(t *testing.T) {
	parsed := token.Token{
		Claims: claim.Claims{
			Subject:  "camera-front",
			Username: "front",
		},
	}

	parser := &fakeParser{
		result: parsed,
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	_, err = authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"unexpected validator call count: got %d, want 1",
			validation.calls,
		)
	}

	if validation.request.Token.Claims.Subject != parsed.Claims.Subject {
		t.Fatalf(
			"unexpected validated subject: got %q, want %q",
			validation.request.Token.Claims.Subject,
			parsed.Claims.Subject,
		)
	}

	if validation.request.Token.Claims.Username != parsed.Claims.Username {
		t.Fatalf(
			"unexpected validated username: got %q, want %q",
			validation.request.Token.Claims.Username,
			parsed.Claims.Username,
		)
	}
}

func TestAuthenticator_PassesClaimExpressionToValidator(t *testing.T) {
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

	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	_, err = authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
			ClaimExpression: expression,
		},
	)
	if err != nil {
		t.Fatalf(
			"Authenticate() error = %v, want nil",
			err,
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"validator calls = %d, want 1",
			validation.calls,
		)
	}

	if validation.request.ClaimExpression != expression {
		t.Fatal(
			"validator received a different claim expression",
		)
	}
}

func TestAuthenticator_AcceptsSatisfiedClaimExpression(t *testing.T) {
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

	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(
			&recordingValidator{},
		),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
			ClaimExpression: expression,
		},
	)
	if err != nil {
		t.Fatalf(
			"Authenticate() error = %v, want nil",
			err,
		)
	}

	if identity.Subject != "camera-front" {
		t.Fatalf(
			"identity subject = %q, want %q",
			identity.Subject,
			"camera-front",
		)
	}
}

func TestAuthenticator_RejectsUnsatisfiedClaimExpression(t *testing.T) {
	expression, err := claim.NewMatch(
		claim.NameSubject,
		claim.OperatorEqual,
		"camera-back",
	)
	if err != nil {
		t.Fatalf(
			"NewMatch() error = %v, want nil",
			err,
		)
	}

	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
			ClaimExpression: expression,
		},
	)

	if !errors.Is(
		err,
		ErrAuthentication,
	) {
		t.Fatalf(
			"Authenticate() error = %v, want ErrAuthentication",
			err,
		)
	}

	if !errors.Is(
		err,
		validator.ErrClaimExpressionNotSatisfied,
	) {
		t.Fatalf(
			"Authenticate() error = %v, want ErrClaimExpressionNotSatisfied",
			err,
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"validator calls = %d, want 1",
			validation.calls,
		)
	}

	if identity != (Identity{}) {
		t.Fatalf(
			"identity = %+v, want empty identity",
			identity,
		)
	}
}

func TestAuthenticator_ParserErrorStopsValidation(t *testing.T) {
	parser := &fakeParser{
		err: token.ErrInvalidSignature,
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)

	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf(
			"expected ErrAuthentication, got %v",
			err,
		)
	}

	if !errors.Is(err, token.ErrInvalidSignature) {
		t.Fatalf(
			"expected token.ErrInvalidSignature, got %v",
			err,
		)
	}

	if validation.calls != 0 {
		t.Fatalf(
			"validator must not be called after parser failure: got %d calls",
			validation.calls,
		)
	}

	if identity != (Identity{}) {
		t.Fatalf(
			"expected empty identity, got %+v",
			identity,
		)
	}
}

func TestAuthenticator_ValidatorErrorPropagation(t *testing.T) {
	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	validation := &recordingValidator{
		err: validator.ErrExpired,
	}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)

	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf(
			"expected ErrAuthentication, got %v",
			err,
		)
	}

	if !errors.Is(err, validator.ErrExpired) {
		t.Fatalf(
			"expected validator.ErrExpired, got %v",
			err,
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"unexpected validator call count: got %d, want 1",
			validation.calls,
		)
	}

	if identity != (Identity{}) {
		t.Fatalf(
			"expected empty identity, got %+v",
			identity,
		)
	}
}

func TestAuthenticator_ParserCancellationIsNotAuthenticationFailure(
	t *testing.T,
) {
	parser := &fakeParser{
		err: context.Canceled,
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"expected context.Canceled, got %v",
			err,
		)
	}

	if errors.Is(err, ErrAuthentication) {
		t.Fatalf(
			"context cancellation must not be classified as authentication failure: %v",
			err,
		)
	}

	if validation.calls != 0 {
		t.Fatalf(
			"validator must not be called after parser cancellation: got %d calls",
			validation.calls,
		)
	}

	if identity != (Identity{}) {
		t.Fatalf(
			"expected empty identity, got %+v",
			identity,
		)
	}
}

func TestAuthenticator_ValidatorDeadlineIsNotAuthenticationFailure(
	t *testing.T,
) {
	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	validation := &recordingValidator{
		err: context.DeadlineExceeded,
	}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf(
			"expected context.DeadlineExceeded, got %v",
			err,
		)
	}

	if errors.Is(err, ErrAuthentication) {
		t.Fatalf(
			"context deadline must not be classified as authentication failure: %v",
			err,
		)
	}

	if identity != (Identity{}) {
		t.Fatalf(
			"expected empty identity, got %+v",
			identity,
		)
	}
}

func TestAuthenticator_PropagatesContext(t *testing.T) {
	ctx := context.WithValue(
		context.Background(),
		testContextKey,
		"context-value",
	)

	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	_, err = authenticator.Authenticate(
		ctx,
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if parser.ctx.Value(testContextKey) != "context-value" {
		t.Fatal("expected context to be propagated to parser")
	}

	if validation.ctx.Value(testContextKey) != "context-value" {
		t.Fatal("expected context to be propagated to validator")
	}
}

func TestAuthenticator_RejectsIdentityWithoutSubject(t *testing.T) {
	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Username: "front",
				Email:    "front@example.com",
			},
		},
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)

	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf(
			"expected ErrAuthentication, got %v",
			err,
		)
	}

	if !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf(
			"expected ErrInvalidIdentity, got %v",
			err,
		)
	}

	if validation.calls != 1 {
		t.Fatalf(
			"unexpected validator call count: got %d, want 1",
			validation.calls,
		)
	}

	if identity != (Identity{}) {
		t.Fatalf(
			"expected empty identity, got %+v",
			identity,
		)
	}
}

func TestAuthenticator_IdentityMapping(t *testing.T) {
	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject:  "camera-front",
				Username: "front",
				Email:    "front@example.com",
			},
		},
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	want := Identity{
		Subject:  "camera-front",
		Username: "front",
		Email:    "front@example.com",
	}

	if identity != want {
		t.Fatalf(
			"unexpected identity: got %+v, want %+v",
			identity,
			want,
		)
	}
}

func TestAuthenticator_MachineIdentityAllowsOptionalFields(t *testing.T) {
	parser := &fakeParser{
		result: token.Token{
			Claims: claim.Claims{
				Subject: "camera-front",
			},
		},
	}

	validation := &recordingValidator{}

	authenticator, err := NewAuthenticator(
		parser,
		validator.NewProvider(validation),
	)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	identity, err := authenticator.Authenticate(
		context.Background(),
		Request{
			Credential: Credential{
				Value: "token",
			},
		},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	want := Identity{
		Subject: "camera-front",
	}

	if identity != want {
		t.Fatalf(
			"unexpected machine identity: got %+v, want %+v",
			identity,
			want,
		)
	}
}
