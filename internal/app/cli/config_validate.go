package cli

import (
	"fmt"

	cliconfig "simple-jwt-authenticator/internal/config/cli"
	serverconfig "simple-jwt-authenticator/internal/config/server"
	transport "simple-jwt-authenticator/internal/transport/cli"
)

// configValidate implements the concrete behavior behind `config validate`.
//
// The CLI adapter owns the validation-mode syntax. This composition root owns
// the mapping from that syntax to concrete configuration contracts.
type configValidate struct{}

// Validate implements cli.ConfigValidate.
//
// Mode dispatch happens before any file access. An unsupported mode therefore
// fails closed and cannot accidentally cause a configuration file to be
// interpreted using an unintended schema.
func (configValidate) Validate(
	path string,
	mode transport.ConfigValidationMode,
) error {
	switch mode {
	case transport.ConfigValidationModeServer:
		_, err := serverconfig.LoadValidated(
			path,
		)

		return err

	case transport.ConfigValidationModeTokenGenerate:
		_, err := cliconfig.LoadForTokenGenerate(
			path,
		)

		return err

	case transport.ConfigValidationModeTokenValidate:
		_, err := cliconfig.LoadForTokenValidate(
			path,
		)

		return err

	default:
		return fmt.Errorf(
			"unsupported configuration validation mode %q",
			mode,
		)
	}
}
