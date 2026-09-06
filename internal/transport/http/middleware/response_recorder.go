package middleware

import (
	stdhttp "net/http"
)

// responseRecorder wraps an HTTP response writer and records the first
// response status written by the downstream handler.
//
// The recorder is shared by HTTP metrics and access logging so both
// observability layers use identical net/http status semantics.
//
// A handler that writes a body without first calling WriteHeader implicitly
// produces HTTP 200. A handler that returns without writing anything is also
// observed by net/http as an empty HTTP 200 response.
type responseRecorder struct {
	stdhttp.ResponseWriter

	status    int
	wroteHead bool
}

// newResponseRecorder constructs a response recorder around writer.
func newResponseRecorder(
	writer stdhttp.ResponseWriter,
) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: writer,
	}
}

// WriteHeader records the first HTTP status and forwards the call.
//
// Only the first status is retained because that is the status committed to
// the client by net/http. Subsequent calls are still forwarded so this wrapper
// does not invent behavior that differs from the underlying writer.
func (r *responseRecorder) WriteHeader(
	statusCode int,
) {
	if !r.wroteHead {
		r.status = statusCode
		r.wroteHead = true
	}

	r.ResponseWriter.WriteHeader(
		statusCode,
	)
}

// Write records an implicit HTTP 200 when the response body is written before
// an explicit WriteHeader call.
func (r *responseRecorder) Write(
	data []byte,
) (int, error) {
	if !r.wroteHead {
		r.status = stdhttp.StatusOK
		r.wroteHead = true
	}

	return r.ResponseWriter.Write(
		data,
	)
}

// Status returns the HTTP status observed for the response.
//
// When the downstream handler returned without writing either headers or a
// body, net/http serves an empty HTTP 200 response. The recorder mirrors that
// externally observable behavior.
func (r *responseRecorder) Status() int {
	if r.status == 0 {
		return stdhttp.StatusOK
	}

	return r.status
}

// Unwrap exposes the underlying ResponseWriter to net/http.ResponseController
// and other standard-library facilities that understand wrapper unwrapping.
//
// Observability middleware must not unnecessarily hide transport capabilities
// provided by the original ResponseWriter.
func (r *responseRecorder) Unwrap() stdhttp.ResponseWriter {
	return r.ResponseWriter
}
