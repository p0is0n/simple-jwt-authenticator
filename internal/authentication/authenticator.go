// Package authentication is transport-independent. It owns the concrete
// Authenticator that turns a neutral Credential into a normalized Identity
// using a token.Parser and a validator.Provider.
//
// It must not know about HTTP, Nginx, cookies, Authorization headers,
// Prometheus, or any concrete JWT implementation.
package authentication

import (
	"context"
	"errors"
	"fmt"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/validator"
)

// Authenticator is the transport-independent authentication core.
//
// It parses a credential exactly once, validates the resulting token through
// an ordered validator chain, and maps validated claims to a normalized
// Identity.
type Authenticator struct {
	parser    token.Parser
	validator *validator.Provider
}

// NewAuthenticator constructs an Authenticator.
//
// Parser and validators are mandatory dependencies. The validator provider is
// expected to contain the complete validation policy required by the
// application.
func NewAuthenticator(
	parser token.Parser,
	validator *validator.Provider,
) (*Authenticator, error) {
	if parser == nil {
		return nil, fmt.Errorf(
			"%w: token parser is required",
			ErrInvalidConfiguration,
		)
	}

	if validator == nil {
		return nil, fmt.Errorf(
			"%w: validator provider is required",
			ErrInvalidConfiguration,
		)
	}

	return &Authenticator{
		parser:    parser,
		validator: validator,
	}, nil
}

// Authenticate parses the credential, validates the resulting token, and
// returns a normalized Identity.
//
// Authentication fails closed when the credential is empty or the validated
// token cannot produce an identity with a subject.
func (a *Authenticator) Authenticate(
	ctx context.Context,
	request Request,
) (Identity, error) {
	if request.Credential.Value == "" {
		return Identity{}, fmt.Errorf(
			"%w: %w",
			ErrAuthentication,
			ErrMissingCredential,
		)
	}

	parsedToken, err := a.parser.Parse(
		ctx,
		token.ParseRequest{
			Value: request.Credential.Value,
		},
	)
	if err != nil {
		return Identity{}, wrapAuthenticationError(
			"parse token",
			err,
		)
	}

	if err := a.validator.Validate(
		ctx,
		validator.Request{
			Token:           parsedToken,
			ClaimExpression: request.ClaimExpression,
		},
	); err != nil {
		return Identity{}, wrapAuthenticationError(
			"validate token",
			err,
		)
	}

	claims := parsedToken.Claims
	if claims.Subject == "" {
		return Identity{}, fmt.Errorf(
			"%w: %w",
			ErrAuthentication,
			ErrInvalidIdentity,
		)
	}

	return Identity{
		Subject:  claims.Subject,
		Username: claims.Username,
		Email:    claims.Email,
	}, nil
}

func wrapAuthenticationError(operation string, err error) error {
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", operation, err)
	}

	return fmt.Errorf(
		"%w: %s: %w",
		ErrAuthentication,
		operation,
		err,
	)
}
