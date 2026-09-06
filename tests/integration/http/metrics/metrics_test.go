//go:build integration

package metrics_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"simple-jwt-authenticator/tests/integration/support/authenticator"
)

func TestMetricsEndpointReturnsPrometheusMetrics(t *testing.T) {
	resp, err := testEnv.client.Get(
		testEnv.authURL + authenticator.MetricsPath,
	)
	if err != nil {
		t.Fatalf(
			"metrics request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf(
			"read metrics body: %v",
			err,
		)
	}

	content := string(body)

	if !strings.Contains(content, "# HELP ") {
		t.Fatal(
			"expected Prometheus HELP declarations",
		)
	}

	if !strings.Contains(content, "# TYPE ") {
		t.Fatal(
			"expected Prometheus TYPE declarations",
		)
	}

	if !strings.Contains(
		content,
		"simple_jwt_authenticator_",
	) {
		t.Fatal(
			"expected project metrics",
		)
	}
}

func TestMetricsEndpointUsesPrometheusContentType(t *testing.T) {
	resp, err := testEnv.client.Get(
		testEnv.authURL + authenticator.MetricsPath,
	)
	if err != nil {
		t.Fatalf(
			"metrics request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	contentType := resp.Header.Get(
		"Content-Type",
	)

	if !strings.HasPrefix(
		contentType,
		"text/plain",
	) && !strings.HasPrefix(
		contentType,
		"application/openmetrics-text",
	) {
		t.Fatalf(
			"expected Prometheus content type, got %q",
			contentType,
		)
	}
}

func TestMetricsEndpointRejectsNestedPath(t *testing.T) {
	resp, err := testEnv.client.Get(
		testEnv.authURL +
			authenticator.MetricsPath +
			"/details",
	)
	if err != nil {
		t.Fatalf(
			"nested metrics request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNotFound,
			resp.StatusCode,
		)
	}
}
