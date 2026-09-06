package cli

import (
	"fmt"
)

// LoadForTokenGenerate loads a CLI configuration and validates the complete
// configuration contract required by the `token generate` use case.
//
// Callers outside this package should prefer this function over manually
// composing Load and ValidateTokenGenerate. Keeping that pipeline here
// guarantees that every token-generation entrypoint uses identical loading,
// defaulting and semantic-validation behavior.
func LoadForTokenGenerate(
	path string,
) (Config, error) {
	appConfig, err := Load(
		path,
	)
	if err != nil {
		return Config{}, fmt.Errorf(
			"load CLI config: %w",
			err,
		)
	}

	if err := ValidateTokenGenerate(
		appConfig,
	); err != nil {
		return Config{}, fmt.Errorf(
			"validate CLI config for token generation: %w",
			err,
		)
	}

	return appConfig, nil
}

// LoadForTokenValidate loads a CLI configuration and validates the complete
// configuration contract required by the `token validate` use case.
//
// Token validation intentionally has a separate loading entrypoint from token
// generation because the two commands require different key capabilities and
// therefore different semantic configuration contracts.
func LoadForTokenValidate(
	path string,
) (Config, error) {
	appConfig, err := Load(
		path,
	)
	if err != nil {
		return Config{}, fmt.Errorf(
			"load CLI config: %w",
			err,
		)
	}

	if err := ValidateTokenValidate(
		appConfig,
	); err != nil {
		return Config{}, fmt.Errorf(
			"validate CLI config for token validation: %w",
			err,
		)
	}

	return appConfig, nil
}
