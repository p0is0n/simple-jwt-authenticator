// Package extractor owns the concrete HTTP credential extractors.
//
// Extractors distinguish "not applicable" from a terminal extraction error
// so the credential provider can implement ordered fallback behavior.
package extractor

import (
	"errors"
	"strings"

	stdhttp "net/http"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

// AuthorizationHeader extracts a Bearer credential from the Authorization
// header.
//
// Behavior:
//
//	header absent        -> not applicable
//	valid Bearer scheme  -> extracted
//	header malformed     -> terminal error
//
// A syntactically valid Bearer value containing a malformed token is still
// an extracted credential. Token parsing and validation happen after HTTP
// credential extraction and must not be performed by this extractor.
type AuthorizationHeader struct{}

// Extract implements credential.Extractor.
func (AuthorizationHeader) Extract(
	request *stdhttp.Request,
) (credential.Result, error) {
	headers := request.Header.Values("Authorization")
	if len(headers) == 0 {
		return notApplicable(), nil
	}

	if len(headers) > 1 {
		return credential.Result{
				Source: credential.SourceAuthorizationHeader,
			},
			errors.Join(
				credential.ErrMalformedCredential,
			)
	}

	header := headers[0]
	const scheme = "Bearer"

	schemePart, tokenPart, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(schemePart, scheme) {
		return credential.Result{
				Source: credential.SourceAuthorizationHeader,
			},
			errors.Join(
				credential.ErrMalformedCredential,
				errInvalidAuthorizationScheme,
			)
	}

	token := strings.TrimSpace(tokenPart)
	if token == "" {
		return credential.Result{
				Source: credential.SourceAuthorizationHeader,
			},
			errors.Join(
				credential.ErrMalformedCredential,
				errEmptyBearerToken,
			)
	}

	return extracted(token), nil
}

// notApplicable returns a not-applicable result for the Authorization
// header source.
func notApplicable() credential.Result {
	return credential.Result{
		Source:        credential.SourceAuthorizationHeader,
		NotApplicable: true,
	}
}

// extracted returns an extracted result for the Authorization header source.
func extracted(value string) credential.Result {
	return credential.Result{
		Credential: authentication.Credential{
			Value: token.Value(value),
		},
		Source:    credential.SourceAuthorizationHeader,
		Extracted: true,
	}
}

var (
	errInvalidAuthorizationScheme = errors.New(
		"authorization scheme is not Bearer",
	)

	errEmptyBearerToken = errors.New(
		"bearer token is empty",
	)
)
