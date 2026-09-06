package middleware

import (
	"log/slog"
	stdhttp "net/http"
	"time"
)

// Logging writes one structured access-log event after each HTTP request has
// completed.
//
// The middleware deliberately records only bounded operational metadata:
//
//	request_id
//	route
//	method
//	status
//	duration
//
// It must not log raw URLs, query strings, request or response bodies,
// Authorization headers, cookies, JWTs, claim expressions, identity claims,
// arbitrary error strings or other request-controlled sensitive values.
//
// The matched route pattern is resolved after downstream handling because
// http.ServeMux populates request.Pattern while routing the request.
func Logging(
	logger *slog.Logger,
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

			logger.InfoContext(
				request.Context(),
				"http request",
				"request_id",
				RequestIDFromContext(
					request.Context(),
				),
				"route",
				handlerIdentity(request),
				"method",
				request.Method,
				"status",
				response.Status(),
				"duration",
				time.Since(start).String(),
			)
		},
	)
}
