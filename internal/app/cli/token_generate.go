package cli

import (
	"context"
	"fmt"

	cliconfig "simple-jwt-authenticator/internal/config/cli"
	"simple-jwt-authenticator/internal/jwt"
	"simple-jwt-authenticator/internal/token"
)

// tokenGenerate implements the concrete token-generation behavior injected
// into the CLI adapter.
type tokenGenerate struct{}

// Generate implements cli.TokenGenerate.
func (tokenGenerate) Generate(
	ctx context.Context,
	configPath string,
	request token.GenerateRequest,
) (token.SerializedToken, error) {
	appConfig, err := cliconfig.LoadForTokenGenerate(
		configPath,
	)
	if err != nil {
		return token.SerializedToken{}, err
	}

	generator, err := buildGenerator(
		appConfig,
	)
	if err != nil {
		return token.SerializedToken{}, err
	}

	return generator.Generate(
		ctx,
		request,
	)
}

// buildGenerator constructs the concrete JWT generator from an already
// validated token-generation configuration.
//
// Separating configuration loading from dependency construction keeps this
// function deterministic with respect to configuration I/O and makes the
// composition boundary easier to test.
func buildGenerator(
	appConfig cliconfig.Config,
) (token.Generator, error) {
	algorithm, err := jwt.ParseAlgorithm(
		appConfig.JWT.Algorithm,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse JWT algorithm: %w",
			err,
		)
	}

	signingProvider, err := newSigningProvider(
		appConfig.JWT,
	)
	if err != nil {
		return nil, err
	}

	generator, err := jwt.NewGenerator(
		signingProvider,
		algorithm,
		appConfig.JWT.Issuer,
		appConfig.JWT.DefaultTTL.Std(),
		appConfig.JWT.MaxTTL.Std(),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create JWT generator: %w",
			err,
		)
	}

	return generator, nil
}
