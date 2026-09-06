package middleware

import (
	"log/slog"
	"runtime/debug"

	stdhttp "net/http"
)

// Recovery converts panics in downstream HTTP handling into HTTP 500
// responses.
//
// Panic logging contains only bounded operational metadata. Raw request paths,
// query parameters, credentials, claim expressions, panic values and other
// request-controlled data are deliberately excluded.
//
// Metrics and access logging wrap recovery and therefore observe the final
// HTTP 500 response produced here.
func Recovery(
	logger *slog.Logger,
	next stdhttp.Handler,
) stdhttp.Handler {
	return stdhttp.HandlerFunc(
		func(
			writer stdhttp.ResponseWriter,
			request *stdhttp.Request,
		) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.ErrorContext(
						request.Context(),
						"recovered from panic",
						"request_id",
						RequestIDFromContext(
							request.Context(),
						),
						"route",
						handlerIdentity(
							request,
						),
						"method",
						request.Method,
					)

					logger.DebugContext(
						request.Context(),
						"panic stack",
						"stack",
						string(
							debug.Stack(),
						),
					)

					// Panic details are intentionally not exposed to clients.
					writer.WriteHeader(
						stdhttp.StatusInternalServerError,
					)

					_, _ = writer.Write(
						[]byte(
							"internal server error",
						),
					)
				}
			}()

			next.ServeHTTP(
				writer,
				request,
			)
		},
	)
}
