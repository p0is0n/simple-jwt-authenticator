// Package prometheus implements the metrics recorder contracts using a
// dedicated Prometheus registry. Generic packages must not import this
// package; the composition root selects it explicitly.
package prometheus

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"simple-jwt-authenticator/internal/metrics"
)

const namespace = "simple_jwt_authenticator"

// Metrics holds the Prometheus collectors for authentication and handled
// operation metrics.
type Metrics struct {
	registry *prometheus.Registry

	authRequests *prometheus.CounterVec
	authDuration *prometheus.HistogramVec

	requests        *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

// New constructs a Metrics instance with a dedicated registry. It must not
// use the process-global default registry.
func New() *Metrics {
	registry := prometheus.NewRegistry()

	m := &Metrics{
		registry: registry,

		authRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "auth_requests_total",
				Help:      "Total number of authentication attempts by adapter, result, source, and reason.",
			},
			[]string{"adapter", "result", "source", "reason"},
		),

		authDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "auth_validation_duration_seconds",
				Help:      "Authentication attempt duration in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"adapter", "result"},
		),

		requests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "requests_total",
				Help:      "Total number of handled operations by handler, operation, and result.",
			},
			[]string{"handler", "operation", "result"},
		),

		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "request_duration_seconds",
				Help:      "Handled operation duration in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"handler", "operation", "result"},
		),
	}

	registry.MustRegister(
		m.authRequests,
		m.authDuration,
		m.requests,
		m.requestDuration,
	)

	return m
}

// Registry returns the dedicated Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// RecordAuth implements metrics.AuthenticationRecorder.
func (m *Metrics) RecordAuth(
	_ context.Context,
	adapter string,
	result metrics.Result,
	source string,
	reason metrics.FailureReason,
	duration time.Duration,
) {
	m.authRequests.WithLabelValues(
		adapter,
		string(result),
		source,
		string(reason),
	).Inc()

	m.authDuration.WithLabelValues(
		adapter,
		string(result),
	).Observe(duration.Seconds())
}

// RecordRequest implements metrics.RequestRecorder.
func (m *Metrics) RecordRequest(
	_ context.Context,
	handler string,
	operation string,
	result metrics.Result,
	duration time.Duration,
) {
	m.requests.WithLabelValues(
		handler,
		operation,
		string(result),
	).Inc()

	m.requestDuration.WithLabelValues(
		handler,
		operation,
		string(result),
	).Observe(duration.Seconds())
}
