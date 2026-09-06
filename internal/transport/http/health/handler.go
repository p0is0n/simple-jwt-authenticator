// Package health exposes the HTTP liveness endpoint.
//
// The endpoint is intentionally independent of authentication, token
// validation, and external dependencies.
package health

import (
	stdhttp "net/http"
)

// Name is the stable handler name.
const Name = "health"

// Path is the route owned by the health handler.
const Path = "/healthz"

// Handler exposes the application liveness endpoint.
//
// Only GET requests are allowed.
type Handler struct{}

// NewHandler constructs a health handler.
func NewHandler() *Handler {
	return &Handler{}
}

// Name returns the stable handler name.
func (Handler) Name() string {
	return Name
}

// Path returns the route owned by the handler.
func (Handler) Path() string {
	return Path
}

// ServeHTTP implements http.Handler.
func (Handler) ServeHTTP(
	writer stdhttp.ResponseWriter,
	request *stdhttp.Request,
) {
	if request.Method != stdhttp.MethodGet {
		writer.WriteHeader(stdhttp.StatusMethodNotAllowed)

		_, _ = writer.Write([]byte("method not allowed\n"))

		return
	}

	writer.WriteHeader(stdhttp.StatusOK)

	_, _ = writer.Write([]byte("ok\n"))
}
