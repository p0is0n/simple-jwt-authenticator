package http

import (
	"log/slog"

	stdhttp "net/http"

	"simple-jwt-authenticator/internal/metrics"
	"simple-jwt-authenticator/internal/transport/http/middleware"
)

// NewHandler composes common middleware around the router.
//
// Runtime order, outer-to-inner:
//
//	RequestID
//	Logging
//	Metrics
//	Recovery
//	Router
//
// RequestID is outermost so every downstream observability layer can
// correlate events with the same request identifier.
//
// Logging wraps metrics and recovery so it observes the final client-visible
// status, including HTTP 500 responses produced by panic recovery.
//
// Metrics also wraps recovery so recovered panics are recorded as failed
// requests rather than escaping before observation.
//
// Construction remains deliberately bottom-up so security-sensitive ordering
// stays visible in source.
func NewHandler(
	logger *slog.Logger,
	requestMetrics metrics.RequestRecorder,
	router stdhttp.Handler,
) stdhttp.Handler {
	handler := middleware.Recovery(
		logger,
		router,
	)

	handler = middleware.Metrics(
		requestMetrics,
		handler,
	)

	handler = middleware.Logging(
		logger,
		handler,
	)

	handler = middleware.RequestID(
		handler,
	)

	return handler
}
