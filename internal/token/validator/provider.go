package validator

import (
	"context"

	"simple-jwt-authenticator/internal/token/claim"
)

// Provider executes configured validators sequentially in their declared order
// and then evaluates optional claim policy.
//
// Validator order may be security-sensitive and is preserved exactly as
// supplied by the caller. Validators are never executed concurrently.
//
// Claim expressions are supplemental policy. They are evaluated only after
// every configured validator succeeds and therefore cannot replace or weaken
// the configured validation chain.
//
// An empty validator chain fails closed.
type Provider struct {
	validators []Validator
}

// NewProvider constructs a Provider from an explicitly ordered validator
// list.
//
// The caller owns validator selection and ordering. Validate rejects an empty
// chain so missing configured validation policy cannot silently authenticate a
// token, even when request-scoped claim policy is present.
func NewProvider(
	validators ...Validator,
) *Provider {
	return &Provider{
		validators: validators,
	}
}

// Validate executes configured validators sequentially and returns the first
// validation error.
//
// After all configured validators succeed, ClaimExpression is evaluated
// against the normalized token claims. A nil expression adds no additional
// policy.
//
// An empty configured chain returns ErrNoValidators. Returning success for an
// empty chain would allow a wiring error to disable mandatory token
// validation.
func (p *Provider) Validate(
	ctx context.Context,
	request Request,
) error {
	if len(p.validators) == 0 {
		return ErrNoValidators
	}

	for _, validation := range p.validators {
		if err := validation.Validate(
			ctx,
			request,
		); err != nil {
			return err
		}
	}

	if !claim.Evaluate(
		request.ClaimExpression,
		request.Token.Claims,
	) {
		return ErrClaimExpressionNotSatisfied
	}

	return nil
}
