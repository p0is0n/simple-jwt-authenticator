// Package middleware owns common HTTP request middleware.
//
// It provides request-id propagation, structured access logging, request
// metrics and panic recovery. Middleware composition remains outside this
// package so runtime ordering stays explicit in the HTTP transport composition
// root.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	stdhttp "net/http"
)

// requestIDKey is the context key for the request-scoped request id.
type requestIDKey struct{}

// RequestIDHeader is the header used to propagate the request id.
const RequestIDHeader = "X-Request-ID"

// maxRequestIDLength bounds accepted inbound request ids to avoid abuse.
const maxRequestIDLength = 128

// RequestID is the outermost middleware. It ensures every request has a
// request id available to downstream middleware and propagates it on the
// response.
//
// Inbound request ids are not blindly trusted. An inbound X-Request-ID is
// accepted only when it is printable, bounded and contains no control
// characters. Otherwise a fresh application-owned identifier is generated.
func RequestID(
	next stdhttp.Handler,
) stdhttp.Handler {
	return stdhttp.HandlerFunc(
		func(
			writer stdhttp.ResponseWriter,
			request *stdhttp.Request,
		) {
			requestID := resolveRequestID(
				request.Header.Get(
					RequestIDHeader,
				),
			)

			request = request.WithContext(
				context.WithValue(
					request.Context(),
					requestIDKey{},
					requestID,
				),
			)

			writer.Header().Set(
				RequestIDHeader,
				requestID,
			)

			next.ServeHTTP(
				writer,
				request,
			)
		},
	)
}

// RequestIDFromContext returns the request id stored in context, or an empty
// string when no request id has been associated with the context.
func RequestIDFromContext(
	ctx context.Context,
) string {
	value, _ := ctx.Value(
		requestIDKey{},
	).(string)

	return value
}

// resolveRequestID returns a safe inbound request id or generates a new one.
func resolveRequestID(
	inbound string,
) string {
	if isSafeRequestID(inbound) {
		return inbound
	}

	return generateRequestID()
}

// isSafeRequestID reports whether an inbound request identifier is safe to
// propagate into application observability.
//
// Control characters are rejected to prevent log/header injection. The value
// is also bounded to prevent abuse of request-scoped metadata.
func isSafeRequestID(
	value string,
) bool {
	if value == "" ||
		len(value) > maxRequestIDLength {
		return false
	}

	for index := 0; index < len(value); index++ {
		character := value[index]

		if character < 0x20 ||
			character == 0x7f {
			return false
		}
	}

	return true
}

// generateRequestID returns a cryptographically random request identifier.
//
// Randomness failure is intentionally treated as unrecoverable. Continuing
// with a predictable or empty request identifier would silently weaken the
// correlation contract used by operational logging.
func generateRequestID() string {
	var bytes [16]byte

	if _, err := rand.Read(
		bytes[:],
	); err != nil {
		panic(
			"generate request id: crypto/rand failed",
		)
	}

	return hex.EncodeToString(
		bytes[:],
	)
}
