package server

import (
	"errors"
	"fmt"

	"simple-jwt-authenticator/internal/config/validation"
)

func validateHTTPServer(server HTTPServer) error {
	var problems []error

	if server.Port < 1 || server.Port > 65535 {
		problems = append(
			problems,
			fmt.Errorf(
				"server.port must be between 1 and 65535, got %d",
				server.Port,
			),
		)
	}

	if err := validation.PositiveDuration(
		"server.read_timeout",
		server.ReadTimeout,
	); err != nil {
		problems = append(problems, err)
	}

	if err := validation.PositiveDuration(
		"server.read_header_timeout",
		server.ReadHeaderTimeout,
	); err != nil {
		problems = append(problems, err)
	}

	if err := validation.PositiveDuration(
		"server.write_timeout",
		server.WriteTimeout,
	); err != nil {
		problems = append(problems, err)
	}

	if err := validation.PositiveDuration(
		"server.idle_timeout",
		server.IdleTimeout,
	); err != nil {
		problems = append(problems, err)
	}

	if err := validation.PositiveDuration(
		"server.shutdown_timeout",
		server.ShutdownTimeout,
	); err != nil {
		problems = append(problems, err)
	}

	if server.MaxHeaderBytes <= 0 {
		problems = append(
			problems,
			fmt.Errorf(
				"server.max_header_bytes must be positive, got %d",
				server.MaxHeaderBytes,
			),
		)
	}

	return errors.Join(problems...)
}
