// Package metrics owns transport-neutral observability contracts.
//
// Transport implementations adapt their native semantics into these
// contracts at the transport boundary. The package must not depend on HTTP,
// gRPC, or other transport-specific types.
package metrics

import (
	"context"
	"time"
)

// AuthenticationRecorder records authentication attempts at the
// authentication adapter boundary.
//
// The adapter boundary is the first layer that observes the complete
// authentication attempt, including failures that occur before the core
// authenticator is called, such as malformed credentials.
//
// Adapter, source, result, and reason values must be bounded and suitable
// for use as metric labels. Raw credentials, identity values, error
// messages, and other unbounded values must never be passed through this
// contract.
type AuthenticationRecorder interface {
	RecordAuth(
		ctx context.Context,
		adapter string,
		result Result,
		source string,
		reason FailureReason,
		duration time.Duration,
	)
}

// RequestRecorder records execution metrics for handled operations.
//
// The contract is intentionally transport-neutral. It does not expose HTTP
// requests, HTTP methods, status codes, gRPC statuses, or other
// transport-specific concepts.
//
// Transport boundaries are responsible for translating their native
// semantics into the normalized fields accepted here. For example, HTTP
// middleware may map the request method to operation and the resulting HTTP
// status into Result before calling RecordRequest.
//
// All values passed to the recorder must be bounded and suitable for use as
// metric labels. Request-specific, identity-specific, credential, or other
// high-cardinality values must not be passed through this contract.
type RequestRecorder interface {
	RecordRequest(
		ctx context.Context,
		handler string,
		operation string,
		result Result,
		duration time.Duration,
	)
}
