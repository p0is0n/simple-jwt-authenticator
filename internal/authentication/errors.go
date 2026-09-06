package authentication

import "errors"

var (
	// ErrAuthentication is the sentinel returned for authentication failures.
	//
	// The concrete rejection cause is preserved in the error chain so callers
	// can classify it with errors.Is or errors.As.
	ErrAuthentication = errors.New("authentication failed")

	// ErrInvalidConfiguration indicates that Authenticator cannot be safely
	// constructed from the supplied dependencies.
	ErrInvalidConfiguration = errors.New("invalid authentication configuration")

	// ErrMissingCredential indicates that authentication was requested without
	// a credential value.
	ErrMissingCredential = errors.New("credential is missing")

	// ErrInvalidIdentity indicates that validated token claims cannot produce
	// the minimum identity required by the authentication core.
	ErrInvalidIdentity = errors.New("identity subject is missing")
)
