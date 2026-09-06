package server

import (
	"fmt"
)

// LoadValidated loads and semantically validates a server configuration.
//
// Callers that intend to run or explicitly validate the server should use
// this entrypoint rather than manually composing Load and Validate. Keeping
// the complete configuration pipeline inside this package prevents different
// application entrypoints from accidentally applying different validation
// behavior.
func LoadValidated(
	path string,
) (Config, error) {
	appConfig, err := Load(
		path,
	)
	if err != nil {
		return Config{}, fmt.Errorf(
			"load server config: %w",
			err,
		)
	}

	if err := Validate(
		appConfig,
	); err != nil {
		return Config{}, fmt.Errorf(
			"validate server config: %w",
			err,
		)
	}

	return appConfig, nil
}
