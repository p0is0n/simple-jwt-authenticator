// Package metrics exposes the HTTP endpoint used to serve application
// metrics.
//
// Generic metrics recorder contracts live in internal/metrics. This package
// only adapts a configured exposition handler into the common HTTP handler
// contract.
package metrics

import (
	stdhttp "net/http"
)

// Name is the stable handler name.
const Name = "metrics"

// Handler exposes the metrics endpoint at a configured path.
//
// Only GET requests are allowed.
type Handler struct {
	path string
	next stdhttp.Handler
}

// NewHandler constructs a metrics handler bound to the configured path and
// exposition handler.
func NewHandler(
	path string,
	next stdhttp.Handler,
) *Handler {
	return &Handler{
		path: path,
		next: next,
	}
}

// Name returns the stable handler name.
func (*Handler) Name() string {
	return Name
}

// Path returns the route owned by the handler.
func (h *Handler) Path() string {
	return h.path
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(
	writer stdhttp.ResponseWriter,
	request *stdhttp.Request,
) {
	if request.Method != stdhttp.MethodGet {
		writer.WriteHeader(stdhttp.StatusMethodNotAllowed)

		_, _ = writer.Write([]byte("method not allowed\n"))

		return
	}

	h.next.ServeHTTP(writer, request)
}
