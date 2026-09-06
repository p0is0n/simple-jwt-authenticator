//go:build integration

package nginx_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestInternalAuthEndpointCannotBeAccessedDirectly(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/_auth",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request internal auth endpoint: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf(
			"direct auth endpoint access: expected %d, got %d",
			http.StatusNotFound,
			resp.StatusCode,
		)
	}
}

func TestProtectedRequestMethodAndBodyPreserved(t *testing.T) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	const requestBody = `{"command":"open"}`

	req, err := http.NewRequest(
		http.MethodPost,
		testEnv.baseURL+"/anything",
		strings.NewReader(requestBody),
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"expected %d from protected upstream, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	var body struct {
		Method string `json:"method"`
		Data   string `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode upstream response: %v", err)
	}

	if body.Method != http.MethodPost {
		t.Fatalf(
			"expected upstream method %q, got %q",
			http.MethodPost,
			body.Method,
		)
	}

	if body.Data != requestBody {
		t.Fatalf(
			"expected upstream body %q, got %q",
			requestBody,
			body.Data,
		)
	}
}

func TestProtectedRequestQueryStringPreserved(t *testing.T) {
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
		testEnv.baseURL+"/get?camera=front&mode=live",
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

	var body struct {
		Args url.Values `json:"args"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode upstream response: %v", err)
	}

	if got := body.Args.Get("camera"); got != "front" {
		t.Fatalf(
			"expected camera query value %q, got %q",
			"front",
			got,
		)
	}

	if got := body.Args.Get("mode"); got != "live" {
		t.Fatalf(
			"expected mode query value %q, got %q",
			"live",
			got,
		)
	}
}

func TestRejectedRequestDoesNotExposeIdentityHeaders(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set("X-Auth-Subject", "attacker")
	req.Header.Set("X-Auth-Username", "attacker")
	req.Header.Set("X-Auth-Email", "attacker@example.com")

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}

	for _, name := range []string{
		"X-Auth-Subject",
		"X-Auth-Username",
		"X-Auth-Email",
	} {
		if got := resp.Header.Get(name); got != "" {
			t.Fatalf(
				"rejected response must not expose %s, got %q",
				name,
				got,
			)
		}
	}
}

func TestBearerCredentialNotForwardedToProtectedUpstream(t *testing.T) {
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

	if got := headers.Get("Authorization"); got != "" {
		t.Fatalf(
			"Authorization credential leaked to protected upstream: %q",
			got,
		)
	}

	if got := headers.Get("X-Auth-Subject"); got != "camera-front" {
		t.Fatalf(
			"expected normalized identity subject %q, got %q",
			"camera-front",
			got,
		)
	}
}

func TestAuthenticationCookieNotForwardedToProtectedUpstream(t *testing.T) {
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

	req.AddCookie(&http.Cookie{
		Name:  "auth_token_test",
		Value: token,
	})

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

	if got := headers.Get("Cookie"); got != "" {
		t.Fatalf(
			"authentication cookie leaked to protected upstream: %q",
			got,
		)
	}

	if got := headers.Get("X-Auth-Subject"); got != "camera-front" {
		t.Fatalf(
			"expected normalized identity subject %q, got %q",
			"camera-front",
			got,
		)
	}
}

func TestProtectedRequestBodyIsNotConsumedByAuthSubrequest(t *testing.T) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	// Keep this payload large enough to exercise request-body forwarding
	// beyond a trivial one-line request while remaining textual. Using a
	// textual Content-Type is intentional: go-httpbin may represent binary
	// request bodies differently in its JSON response, which would test its
	// serialization behavior instead of the Nginx auth_request boundary.
	payload := bytes.Repeat(
		[]byte("integration-body-"),
		1024,
	)

	req, err := http.NewRequest(
		http.MethodPost,
		testEnv.baseURL+"/anything",
		bytes.NewReader(payload),
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(
		"Content-Type",
		"text/plain; charset=utf-8",
	)

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

	var body struct {
		Data string `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode upstream response: %v", err)
	}

	if !bytes.Equal([]byte(body.Data), payload) {
		t.Fatalf(
			"protected request body changed after authentication: expected %d bytes, got %d",
			len(payload),
			len(body.Data),
		)
	}
}
