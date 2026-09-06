package middleware

import (
	stdhttp "net/http"
	"time"

	"simple-jwt-authenticator/internal/metrics"
)

// Metrics wraps the next HTTP handler and records request execution metrics.
//
// HTTP-specific semantics are normalized at this boundary before being
// passed to the transport-neutral metrics recorder. The request method is
// used as the operation, while the resulting HTTP status code is mapped to
// a bounded success or failure result.
//
// The matched route pattern (request.Pattern) is used as the bounded handler
// identity. Unmatched requests use "unknown".
//
// Raw request URLs, query parameters, credentials, identities and error
// strings must never become metric dimensions.
func Metrics(
	recorder metrics.RequestRecorder,
	next stdhttp.Handler,
) stdhttp.Handler {
	return stdhttp.HandlerFunc(
		func(
			writer stdhttp.ResponseWriter,
			request *stdhttp.Request,
		) {
			response := newResponseRecorder(
				writer,
			)

			start := time.Now()

			next.ServeHTTP(
				response,
				request,
			)

			recorder.RecordRequest(
				request.Context(),
				handlerIdentity(request),
				request.Method,
				requestResult(response.Status()),
				time.Since(start),
			)
		},
	)
}

// requestResult maps an HTTP response status into the transport-neutral
// operation result used by the metrics contract.
//
// Informational, successful and redirection responses are treated as
// successful request handling. Client and server errors are failures.
func requestResult(
	statusCode int,
) metrics.Result {
	if statusCode >= stdhttp.StatusBadRequest {
		return metrics.ResultFailure
	}

	return metrics.ResultSuccess
}

// handlerIdentity returns the bounded identity of the route selected by the
// standard HTTP router.
//
// request.Pattern is populated by http.ServeMux after routing. Unlike the raw
// request path it cannot contain arbitrary path data when routes are defined
// using bounded application-owned patterns.
//
// Requests that did not match any route are deliberately collapsed to
// "unknown" rather than exposing arbitrary attacker-controlled paths to
// observability systems.
func handlerIdentity(
	request *stdhttp.Request,
) string {
	if request.Pattern != "" {
		return request.Pattern
	}

	return "unknown"
}
