package nginx

import (
	stdhttp "net/http"

	httptransport "simple-jwt-authenticator/internal/transport/http"
)

// HeaderName constants identify the authentication headers exposed to Nginx
// after successful authentication.
const (
	HeaderSubject  = "X-Auth-Subject"
	HeaderUsername = "X-Auth-Username"
	HeaderEmail    = "X-Auth-Email"
)

// headerMapper is the consumer-owned contract for mapping an authenticated
// adapter-local identity into response headers.
type headerMapper interface {
	Apply(
		response stdhttp.Header,
		identity identity,
	) error
}

// identity is the narrow adapter-local representation required for response
// mapping.
type identity struct {
	Subject  string
	Username string
	Email    string
}

// defaultHeaderMapper maps authenticated identity data to response headers.
//
// Mapping is atomic: every value is validated before any response header is
// mutated. Invalid values are rejected rather than sanitized.
type defaultHeaderMapper struct{}

// Apply implements headerMapper.
func (defaultHeaderMapper) Apply(
	response stdhttp.Header,
	id identity,
) error {
	if id.Subject == "" {
		return errMissingIdentitySubject
	}

	if !httptransport.IsSafeHeaderValue(
		id.Subject,
	) {
		return errUnsafeHeaderValue
	}

	if id.Username != "" &&
		!httptransport.IsSafeHeaderValue(
			id.Username,
		) {
		return errUnsafeHeaderValue
	}

	if id.Email != "" &&
		!httptransport.IsSafeHeaderValue(
			id.Email,
		) {
		return errUnsafeHeaderValue
	}

	response.Set(
		HeaderSubject,
		id.Subject,
	)

	if id.Username != "" {
		response.Set(
			HeaderUsername,
			id.Username,
		)
	}

	if id.Email != "" {
		response.Set(
			HeaderEmail,
			id.Email,
		)
	}

	return nil
}
