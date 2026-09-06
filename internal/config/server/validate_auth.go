package server

import (
	"errors"
	"fmt"

	"simple-jwt-authenticator/internal/config/validation"
)

func validateAuth(
	auth Auth,
) error {
	var problems []error

	if !auth.Handlers.HTTP.Nginx.Enabled {
		problems = append(
			problems,
			fmt.Errorf(
				"at least one authentication handler must be enabled",
			),
		)
	}

	enabledExtractors := 0
	if auth.Extractors.HTTP.AuthorizationHeader.Enabled {
		enabledExtractors++
	}

	if auth.Extractors.HTTP.Cookie.Enabled {
		enabledExtractors++

		if err := validation.CanonicalNonEmptyString(
			"auth.extractors.http.cookie.name",
			auth.Extractors.HTTP.Cookie.Name,
		); err != nil {
			problems = append(
				problems,
				err,
			)
		}
	}

	if enabledExtractors == 0 {
		problems = append(
			problems,
			fmt.Errorf(
				"at least one credential extractor must be enabled",
			),
		)
	}

	return errors.Join(problems...)
}
