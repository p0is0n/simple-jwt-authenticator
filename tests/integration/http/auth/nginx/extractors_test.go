//go:build integration

package nginx_test

import (
	"net/http"
	"testing"
)

func TestValidCookieAllowed(t *testing.T) {
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
			"valid cookie: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestInvalidCookieBlocked(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "auth_token_test",
		Value: "definitely-not-a-jwt",
	})

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"invalid cookie: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestAuthorizationPrecedenceOverCookie(t *testing.T) {
	headerToken := testEnv.tokens.Generate(
		t,
		"from-header",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	cookieToken := testEnv.tokens.Generate(
		t,
		"from-cookie",
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

	req.Header.Set("Authorization", "Bearer "+headerToken)
	req.AddCookie(&http.Cookie{
		Name:  "auth_token_test",
		Value: cookieToken,
	})

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"authorization precedence: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(t, resp.Body)

	if got := headers.Get("X-Auth-Subject"); got != "from-header" {
		t.Fatalf(
			"expected Authorization credential to take precedence, got subject %q",
			got,
		)
	}
}

func TestValidAuthorizationIgnoresInvalidCookie(t *testing.T) {
	headerToken := testEnv.tokens.Generate(
		t,
		"from-header",
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

	req.Header.Set("Authorization", "Bearer "+headerToken)
	req.AddCookie(&http.Cookie{
		Name:  "auth_token_test",
		Value: "definitely-not-a-jwt",
	})

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"valid Authorization with invalid cookie: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(t, resp.Body)

	if got := headers.Get("X-Auth-Subject"); got != "from-header" {
		t.Fatalf(
			"expected Authorization credential to be used, got subject %q",
			got,
		)
	}
}

func TestMalformedAuthorizationDoesNotFallBackToCookie(t *testing.T) {
	validToken := testEnv.tokens.Generate(
		t,
		"from-cookie",
		"",
		"",
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

	// A present but unsupported Authorization scheme is terminal. Once the
	// higher-priority extractor sees the header, authentication must not
	// silently fall back to the cookie.
	req.Header.Set(
		"Authorization",
		"Basic dXNlcjpwYXNz",
	)

	req.AddCookie(&http.Cookie{
		Name:  "auth_token_test",
		Value: validToken,
	})

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"malformed Authorization with valid cookie: expected %d without cookie fallback, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestEmptyBearerDoesNotFallBackToCookie(t *testing.T) {
	validToken := testEnv.tokens.Generate(
		t,
		"from-cookie",
		"",
		"",
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

	// Authorization is present and explicitly selects Bearer authentication
	// but contains no credential. The higher-priority source is therefore
	// terminal and must not silently fall back to a valid cookie.
	req.Header.Set(
		"Authorization",
		"Bearer",
	)

	req.AddCookie(&http.Cookie{
		Name:  "auth_token_test",
		Value: validToken,
	})

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"empty Bearer with valid cookie: expected %d without cookie fallback, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestMalformedBearerTokenDoesNotFallBackToCookie(t *testing.T) {
	validToken := testEnv.tokens.Generate(
		t,
		"from-cookie",
		"",
		"",
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

	// A Bearer credential selected from the higher-priority Authorization
	// header must remain authoritative even when the JWT itself is invalid.
	// Authentication must not retry with the valid cookie.
	req.Header.Set(
		"Authorization",
		"Bearer definitely-not-a-jwt",
	)

	req.AddCookie(&http.Cookie{
		Name:  "auth_token_test",
		Value: validToken,
	})

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"invalid Bearer token with valid cookie: expected %d without cookie fallback, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}
