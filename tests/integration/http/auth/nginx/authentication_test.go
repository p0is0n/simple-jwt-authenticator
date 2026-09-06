//go:build integration

package nginx_test

import (
	"net/http"
	"testing"
)

func TestValidBearerTokenAllowed(t *testing.T) {
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
		testEnv.baseURL+"/get",
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
			"valid JWT: expected %d from protected upstream, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestMissingCredentialBlocked(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"missing credential: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestMissingCredentialDoesNotReachProtectedUpstream(t *testing.T) {
	// The protected upstream would return 418 for this path. Receiving 401
	// proves that Nginx terminates the request at the authentication boundary
	// instead of forwarding the unauthenticated request.
	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/status/418",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"missing credential for protected 418 endpoint: expected authentication status %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestMalformedTokenBlocked(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// A syntactically valid Bearer value is still an extracted
	// credential; the malformed JWT must be rejected by the parser
	// with 401 from Nginx.
	req.Header.Set(
		"Authorization",
		"Bearer definitely-not-a-jwt",
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"malformed token: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestAuthenticationFailurePropagatesWWWAuthenticate(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer definitely-not-a-jwt",
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"malformed token: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}

	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Fatal(
			"expected WWW-Authenticate from authentication failure, got no header",
		)
	}
}
