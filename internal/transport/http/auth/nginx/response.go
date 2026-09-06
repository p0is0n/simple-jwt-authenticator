package nginx

import (
	stdhttp "net/http"
)

// writeSuccess writes the successful Nginx auth_request response.
func writeSuccess(writer stdhttp.ResponseWriter) {
	writer.WriteHeader(
		stdhttp.StatusNoContent,
	)
}

// writeBadRequest writes a generic malformed-request response.
//
// Dynamic policy details are intentionally not echoed to the caller.
func writeBadRequest(writer stdhttp.ResponseWriter) {
	writer.WriteHeader(
		stdhttp.StatusBadRequest,
	)
}

// writeUnauthorized writes a generic authentication rejection.
//
// No internal error details or response body are exposed.
func writeUnauthorized(writer stdhttp.ResponseWriter) {
	writer.Header().Set(
		"WWW-Authenticate",
		`Bearer realm="simple-jwt-authenticator"`,
	)

	writer.WriteHeader(
		stdhttp.StatusUnauthorized,
	)
}

// writeInternalError writes a generic internal failure response without
// exposing implementation details.
func writeInternalError(writer stdhttp.ResponseWriter) {
	writer.WriteHeader(
		stdhttp.StatusInternalServerError,
	)
}

// writeMethodNotAllowed writes the unsupported-method response and advertises
// the only method accepted by the Nginx authentication endpoint.
func writeMethodNotAllowed(writer stdhttp.ResponseWriter) {
	writer.Header().Set(
		"Allow",
		stdhttp.MethodGet,
	)

	writer.WriteHeader(
		stdhttp.StatusMethodNotAllowed,
	)
}
