package prometheus

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"simple-jwt-authenticator/internal/metrics"
)

func TestNew_UsesDedicatedRegistry(t *testing.T) {
	m := New()

	if m.Registry() == nil {
		t.Fatal("expected non-nil dedicated registry")
	}

	m.RecordRequest(
		context.Background(),
		"health",
		"GET",
		metrics.ResultSuccess,
		0,
	)

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	if len(families) == 0 {
		t.Fatal("expected registered metric families")
	}
}

func TestRecordAuth_ObservesSuccessAndFailure(t *testing.T) {
	m := New()

	m.RecordAuth(
		context.Background(),
		"http-auth-nginx",
		metrics.ResultSuccess,
		"authorization_header",
		"",
		0,
	)

	m.RecordAuth(
		context.Background(),
		"http-auth-nginx",
		metrics.ResultFailure,
		"authorization_header",
		metrics.ReasonExpired,
		0,
	)

	family := gatherMetricFamily(
		t,
		m.Registry(),
		"simple_jwt_authenticator_auth_requests_total",
	)

	assertCounterValue(
		t,
		family,
		map[string]string{
			"adapter": "http-auth-nginx",
			"result":  "success",
			"source":  "authorization_header",
			"reason":  "",
		},
		1,
	)

	assertCounterValue(
		t,
		family,
		map[string]string{
			"adapter": "http-auth-nginx",
			"result":  "failure",
			"source":  "authorization_header",
			"reason":  "expired",
		},
		1,
	)
}

func TestRecordRequest_ObservesRequest(t *testing.T) {
	m := New()

	m.RecordRequest(
		context.Background(),
		"health",
		"GET",
		metrics.ResultSuccess,
		0,
	)

	m.RecordRequest(
		context.Background(),
		"health",
		"POST",
		metrics.ResultFailure,
		0,
	)

	family := gatherMetricFamily(
		t,
		m.Registry(),
		"simple_jwt_authenticator_requests_total",
	)

	assertCounterValue(
		t,
		family,
		map[string]string{
			"handler":   "health",
			"operation": "GET",
			"result":    "success",
		},
		1,
	)

	assertCounterValue(
		t,
		family,
		map[string]string{
			"handler":   "health",
			"operation": "POST",
			"result":    "failure",
		},
		1,
	)
}

func gatherMetricFamily(
	t testing.TB,
	gatherer prometheus.Gatherer,
	name string,
) *dto.MetricFamily {
	t.Helper()

	families, err := gatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}

	t.Fatalf("metric family %q not found", name)

	return nil
}

func assertCounterValue(
	t testing.TB,
	family *dto.MetricFamily,
	expectedLabels map[string]string,
	expectedValue float64,
) {
	t.Helper()

	for _, metric := range family.GetMetric() {
		if !labelsMatch(metric, expectedLabels) {
			continue
		}

		counter := metric.GetCounter()
		if counter == nil {
			t.Fatalf(
				"metric family %q: expected counter metric",
				family.GetName(),
			)
		}

		if got := counter.GetValue(); got != expectedValue {
			t.Fatalf(
				"metric family %q with labels %v: expected value %v, got %v",
				family.GetName(),
				expectedLabels,
				expectedValue,
				got,
			)
		}

		return
	}

	t.Fatalf(
		"metric family %q: metric with labels %v not found",
		family.GetName(),
		expectedLabels,
	)
}

func labelsMatch(
	metric *dto.Metric,
	expected map[string]string,
) bool {
	if len(metric.GetLabel()) != len(expected) {
		return false
	}

	for _, label := range metric.GetLabel() {
		value, ok := expected[label.GetName()]
		if !ok || value != label.GetValue() {
			return false
		}
	}

	return true
}
