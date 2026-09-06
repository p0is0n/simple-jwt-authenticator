//go:build integration

package health_test

import (
	"io"
	"net/http"
	"testing"
)

func TestHealthzReturnsOK(t *testing.T) {
	resp, err := testEnv.client.Get(testEnv.authURL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request: %v", err)
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
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "ok\n" {
		t.Fatalf(
			"expected body %q, got %q",
			"ok\n",
			string(body),
		)
	}
}

func TestHealthzAcceptsQueryString(t *testing.T) {
	resp, err := testEnv.client.Get(
		testEnv.authURL + "/healthz?probe=liveness",
	)
	if err != nil {
		t.Fatalf("healthz request with query: %v", err)
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
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "ok\n" {
		t.Fatalf(
			"expected body %q, got %q",
			"ok\n",
			string(body),
		)
	}
}

func TestHealthzRejectsUnsupportedMethods(t *testing.T) {
	methods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodOptions,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(
				method,
				testEnv.authURL+"/healthz",
				nil,
			)
			if err != nil {
				t.Fatalf("create request: %v", err)
			}

			resp, err := testEnv.client.Do(req)
			if err != nil {
				t.Fatalf("%s healthz request: %v", method, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf(
					"expected status %d, got %d",
					http.StatusMethodNotAllowed,
					resp.StatusCode,
				)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}

			if string(body) != "method not allowed\n" {
				t.Fatalf(
					"expected body %q, got %q",
					"method not allowed\n",
					string(body),
				)
			}
		})
	}
}

func TestHealthzDoesNotMatchNestedPath(t *testing.T) {
	resp, err := testEnv.client.Get(
		testEnv.authURL + "/healthz/details",
	)
	if err != nil {
		t.Fatalf("nested healthz request: %v", err)
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
