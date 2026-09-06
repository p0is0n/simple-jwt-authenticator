package metrics

import (
	"context"
	"time"
)

// NoopAuthenticationRecorder is an allocation-light, behaviorally inert
// AuthenticationRecorder used when authentication metrics are disabled.
type NoopAuthenticationRecorder struct{}

// RecordAuth implements AuthenticationRecorder.
func (NoopAuthenticationRecorder) RecordAuth(
	_ context.Context,
	_ string,
	_ Result,
	_ string,
	_ FailureReason,
	_ time.Duration,
) {
}

// NoopRequestRecorder is an allocation-light, behaviorally inert
// RequestRecorder used when request metrics are disabled.
type NoopRequestRecorder struct{}

// RecordRequest implements RequestRecorder.
func (NoopRequestRecorder) RecordRequest(
	_ context.Context,
	_ string,
	_ string,
	_ Result,
	_ time.Duration,
) {
}

// Noop groups no-op recorder implementations for disabled metrics.
//
// Returning concrete no-op recorders allows callers to avoid nil checks in
// request and authentication paths.
type Noop struct {
	Authentication NoopAuthenticationRecorder
	Requests       NoopRequestRecorder
}

// NewNoop returns no-op recorder implementations for disabled metrics.
func NewNoop() Noop {
	return Noop{
		Authentication: NoopAuthenticationRecorder{},
		Requests:       NoopRequestRecorder{},
	}
}
