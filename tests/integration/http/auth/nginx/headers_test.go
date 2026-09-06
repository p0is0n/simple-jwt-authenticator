//go:build integration

package nginx_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestSubjectHeaderPropagated(t *testing.T) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/headers",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(t, resp.Body)

	if got := headers.Get("X-Auth-Subject"); got != "camera-front" {
		t.Fatalf(
			"expected X-Auth-Subject=%q, got %q",
			"camera-front",
			got,
		)
	}
}

func TestOptionalIdentityHeadersPropagated(t *testing.T) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/headers",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(t, resp.Body)

	if got := headers.Get("X-Auth-Username"); got != "front" {
		t.Fatalf(
			"expected X-Auth-Username=%q, got %q",
			"front",
			got,
		)
	}

	if got := headers.Get("X-Auth-Email"); got != "front@example.com" {
		t.Fatalf(
			"expected X-Auth-Email=%q, got %q",
			"front@example.com",
			got,
		)
	}
}

func TestMachineIdentityOmitsOptionalHeaders(t *testing.T) {
	// Machine identities may contain only a subject. Optional identity
	// headers must be absent from the protected upstream request rather
	// than propagated with empty values.
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/headers",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(t, resp.Body)

	if got := headers.Get("X-Auth-Subject"); got != "camera-front" {
		t.Fatalf(
			"expected X-Auth-Subject=%q, got %q",
			"camera-front",
			got,
		)
	}

	if _, present := headers["X-Auth-Username"]; present {
		t.Fatal(
			"expected X-Auth-Username to be absent for machine identity",
		)
	}

	if _, present := headers["X-Auth-Email"]; present {
		t.Fatal(
			"expected X-Auth-Email to be absent for machine identity",
		)
	}
}

func TestClientIdentityHeadersCannotBeSpoofed(t *testing.T) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/headers",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// Identity headers supplied by the client are untrusted. The Nginx
	// adapter must replace them exclusively with values returned by the
	// authenticator after successful JWT validation.
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Auth-Subject", "attacker")
	req.Header.Set("X-Auth-Username", "attacker")
	req.Header.Set("X-Auth-Email", "attacker@example.com")

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(t, resp.Body)

	if got := headers.Get("X-Auth-Subject"); got != "camera-front" {
		t.Fatalf(
			"expected spoofed X-Auth-Subject to be replaced with %q, got %q",
			"camera-front",
			got,
		)
	}

	if got := headers.Get("X-Auth-Username"); got != "front" {
		t.Fatalf(
			"expected spoofed X-Auth-Username to be replaced with %q, got %q",
			"front",
			got,
		)
	}

	if got := headers.Get("X-Auth-Email"); got != "front@example.com" {
		t.Fatalf(
			"expected spoofed X-Auth-Email to be replaced with %q, got %q",
			"front@example.com",
			got,
		)
	}
}

func TestClientOptionalIdentityHeadersRemovedWhenClaimsAbsent(t *testing.T) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/headers",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// A client must not be able to smuggle optional identity attributes
	// into the protected upstream when those attributes are absent from
	// the validated token.
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Auth-Username", "attacker")
	req.Header.Set("X-Auth-Email", "attacker@example.com")

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(t, resp.Body)

	if got := headers.Get("X-Auth-Subject"); got != "camera-front" {
		t.Fatalf(
			"expected X-Auth-Subject=%q, got %q",
			"camera-front",
			got,
		)
	}

	if _, present := headers["X-Auth-Username"]; present {
		t.Fatal(
			"expected spoofed X-Auth-Username to be removed when claim is absent",
		)
	}

	if _, present := headers["X-Auth-Email"]; present {
		t.Fatal(
			"expected spoofed X-Auth-Email to be removed when claim is absent",
		)
	}
}

// decodeUpstreamHeaders decodes the protected upstream's /headers response
// into an HTTP header map.
func decodeUpstreamHeaders(
	t testing.TB,
	reader io.Reader,
) http.Header {
	t.Helper()

	var body struct {
		Headers http.Header `json:"headers"`
	}

	if err := json.NewDecoder(reader).Decode(&body); err != nil {
		t.Fatalf("decode upstream headers: %v", err)
	}

	return body.Headers
}
