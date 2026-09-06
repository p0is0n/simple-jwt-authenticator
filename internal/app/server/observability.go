package server

import (
	serverconfig "simple-jwt-authenticator/internal/config/server"
	"simple-jwt-authenticator/internal/metrics"
	"simple-jwt-authenticator/internal/metrics/prometheus"
	transportmetrics "simple-jwt-authenticator/internal/transport/http/metrics"
)

// observability contains the observability dependencies required by the
// server graph.
//
// Handler is nil when the metrics endpoint is disabled. Authentication and
// request recorders are always non-nil so downstream components do not need
// metrics-enabled branches.
type observability struct {
	Authentication metrics.AuthenticationRecorder
	Requests       metrics.RequestRecorder
	Handler        *transportmetrics.Handler
}

// newObservability constructs either no-op recorders or the Prometheus-backed
// observability graph.
//
// No Prometheus collectors are constructed when metrics are disabled.
func newObservability(
	metricsConfig serverconfig.Metrics,
) observability {
	if !metricsConfig.Enabled {
		noop := metrics.NewNoop()

		return observability{
			Authentication: noop.Authentication,
			Requests:       noop.Requests,
		}
	}

	prometheusMetrics := prometheus.New()

	return observability{
		Authentication: prometheusMetrics,
		Requests:       prometheusMetrics,
		Handler: transportmetrics.NewHandler(
			metricsConfig.Path,
			prometheusMetrics.Handler(),
		),
	}
}
