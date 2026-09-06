package server

import (
	"fmt"

	serverconfig "simple-jwt-authenticator/internal/config/server"
	"simple-jwt-authenticator/internal/transport/http/credential"
	"simple-jwt-authenticator/internal/transport/http/credential/extractor"
)

// newCredentialProvider constructs the ordered HTTP credential extraction
// chain.
//
// Extraction precedence is security-sensitive and must remain explicit:
//
//	Authorization header
//	Cookie
//
// A malformed terminal Authorization credential must therefore not silently
// fall back to a cookie. The Provider and individual extractors own that
// runtime behavior; this composition root owns their ordering.
//
// Do not replace this sequence with a map or unordered registry.
func newCredentialProvider(
	authConfig serverconfig.Auth,
) (*credential.Provider, error) {
	extractors := make(
		[]credential.Extractor,
		0,
		2,
	)

	if authConfig.Extractors.HTTP.AuthorizationHeader.Enabled {
		extractors = append(
			extractors,
			extractor.AuthorizationHeader{},
		)
	}

	if authConfig.Extractors.HTTP.Cookie.Enabled {
		cookieExtractor, err := extractor.NewCookie(
			authConfig.Extractors.HTTP.Cookie.Name,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"create cookie credential extractor: %w",
				err,
			)
		}

		extractors = append(
			extractors,
			cookieExtractor,
		)
	}

	provider, err := credential.NewProvider(
		extractors...,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"construct credential provider: %w",
			err,
		)
	}

	return provider, nil
}
