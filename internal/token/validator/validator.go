// Package validator owns validation rules operating on normalized token
// representations.
//
// Validators depend only on normalized token contracts and must not depend on
// concrete token formats, cryptographic libraries, or transport concerns.
package validator

import "context"

// Validator applies one validation rule to a normalized validation request.
type Validator interface {
	Validate(
		ctx context.Context,
		request Request,
	) error
}

// Func adapts a function into a Validator.
type Func func(
	ctx context.Context,
	request Request,
) error

// Validate implements Validator.
func (f Func) Validate(
	ctx context.Context,
	request Request,
) error {
	return f(ctx, request)
}
