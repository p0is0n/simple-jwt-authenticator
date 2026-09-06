package cli

import (
	"context"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token"
)

// ConfigValidationMode identifies the configuration contract selected by the
// `config validate --mode` CLI option.
//
// The mode belongs to the CLI transport because it is part of the external
// command-line contract. Mapping it to concrete configuration loaders belongs
// to the composition root.
type ConfigValidationMode string

// Supported configuration validation modes.
const (
	ConfigValidationModeServer        ConfigValidationMode = "server"
	ConfigValidationModeTokenGenerate ConfigValidationMode = "token-generate"
	ConfigValidationModeTokenValidate ConfigValidationMode = "token-validate"
)

// TokenGenerate defines token-generation behavior required by the CLI
// transport.
type TokenGenerate interface {
	Generate(
		ctx context.Context,
		configPath string,
		request token.GenerateRequest,
	) (token.SerializedToken, error)
}

// TokenValidate defines token-validation behavior required by the CLI
// transport.
//
// Request contains the complete transport-independent authentication input.
// Keeping that input grouped prevents the CLI contract from growing a new
// method parameter for every authentication policy extension.
type TokenValidate interface {
	Validate(
		ctx context.Context,
		configPath string,
		request authentication.Request,
	) (authentication.Identity, error)
}

// ConfigValidate defines configuration-validation behavior required by the CLI
// transport.
type ConfigValidate interface {
	Validate(
		path string,
		mode ConfigValidationMode,
	) error
}
