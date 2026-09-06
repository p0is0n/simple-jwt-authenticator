package cli

import (
	"context"
	"fmt"
	"time"

	"simple-jwt-authenticator/internal/authentication"
	cliconfig "simple-jwt-authenticator/internal/config/cli"
	"simple-jwt-authenticator/internal/jwt"
	"simple-jwt-authenticator/internal/token/validator"
)

// tokenValidate implements the concrete token-validation behavior injected
// into the CLI adapter.
type tokenValidate struct{}

// Validate implements cli.TokenValidate.
//
// The CLI transport has already translated external command-line input into
// the transport-independent authentication request, including any optional
// claim expression. The composition root therefore forwards the request
// unchanged and is responsible only for constructing concrete dependencies.
func (tokenValidate) Validate(
	ctx context.Context,
	configPath string,
	request authentication.Request,
) (authentication.Identity, error) {
	appConfig, err := cliconfig.LoadForTokenValidate(
		configPath,
	)
	if err != nil {
		return authentication.Identity{}, err
	}

	authenticator, err := buildAuthenticator(
		appConfig,
	)
	if err != nil {
		return authentication.Identity{}, err
	}

	return authenticator.Authenticate(
		ctx,
		request,
	)
}

// buildAuthenticator constructs the transport-independent authentication core
// from an already validated token-validation configuration.
func buildAuthenticator(
	appConfig cliconfig.Config,
) (*authentication.Authenticator, error) {
	algorithm, err := jwt.ParseAlgorithm(
		appConfig.JWT.Algorithm,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse JWT algorithm: %w",
			err,
		)
	}

	verificationProvider, err := newVerificationProvider(
		appConfig.JWT,
	)
	if err != nil {
		return nil, err
	}

	parser, err := jwt.NewParser(
		verificationProvider,
		algorithm,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create JWT parser: %w",
			err,
		)
	}

	clock := time.Now

	validators := validator.NewProvider(
		validator.RequiredClaims{},
		validator.Expiration{
			Now:  clock,
			Skew: appConfig.JWT.ClockSkew.Std(),
		},
		validator.NotBefore{
			Now:  clock,
			Skew: appConfig.JWT.ClockSkew.Std(),
		},
		validator.IssuedAt{
			Now:  clock,
			Skew: appConfig.JWT.ClockSkew.Std(),
		},
		validator.Issuer{
			Expected: appConfig.JWT.Issuer,
		},
		validator.Audience{
			Expected: appConfig.JWT.Audience,
		},
	)

	authenticator, err := authentication.NewAuthenticator(
		parser,
		validators,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create authenticator: %w",
			err,
		)
	}

	return authenticator, nil
}
