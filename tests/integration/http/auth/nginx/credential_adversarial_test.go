//go:build integration

package nginx_test

import (
	"net/http"
	"testing"
)

func TestDuplicateAuthorizationHeadersFailClosed(
	t *testing.T,
) {
	firstToken := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	secondToken := testEnv.tokens.Generate(
		t,
		"camera-back",
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
		t.Fatalf(
			"create request: %v",
			err,
		)
	}

	req.Header.Add(
		"Authorization",
		"Bearer "+firstToken,
	)
	req.Header.Add(
		"Authorization",
		"Bearer "+secondToken,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		t.Fatal(
			"ambiguous duplicate Authorization headers unexpectedly authenticated",
		)
	}
}

func TestMalformedAuthorizationNeverFallsBackToValidCookie(
	t *testing.T,
) {
	tests := []struct {
		name          string
		authorization string
	}{
		{
			name:          "basic",
			authorization: "Basic dXNlcjpwYXNz",
		},
		{
			name:          "bearer-without-token",
			authorization: "Bearer",
		},
		{
			name:          "bearer-space-only",
			authorization: "Bearer ",
		},
		{
			name:          "malformed-jwt",
			authorization: "Bearer definitely-not-a-jwt",
		},
		{
			name:          "unknown-scheme",
			authorization: "Unknown abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookieToken := testEnv.tokens.Generate(
				t,
				"cookie-identity",
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
				t.Fatalf(
					"create request: %v",
					err,
				)
			}

			req.Header.Set(
				"Authorization",
				tt.authorization,
			)

			req.AddCookie(
				&http.Cookie{
					Name:  "auth_token_test",
					Value: cookieToken,
				},
			)

			resp, err := testEnv.client.Do(req)
			if err != nil {
				t.Fatalf(
					"request: %v",
					err,
				)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusOK {
				t.Fatalf(
					"malformed higher-priority Authorization %q fell back to cookie",
					tt.authorization,
				)
			}
		})
	}
}

func TestUnrelatedCookieDoesNotAffectBearerAuthentication(
	t *testing.T,
) {
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
		testEnv.baseURL+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf(
			"create request: %v",
			err,
		)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	req.AddCookie(
		&http.Cookie{
			Name:  "application_cookie",
			Value: "application-value",
		},
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"unrelated cookie affected Bearer authentication: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestDuplicateAuthenticationCookiesDoNotSelectArbitraryIdentity(
	t *testing.T,
) {
	firstToken := testEnv.tokens.Generate(
		t,
		"first-cookie",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	secondToken := testEnv.tokens.Generate(
		t,
		"second-cookie",
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
		t.Fatalf(
			"create request: %v",
			err,
		)
	}

	req.AddCookie(
		&http.Cookie{
			Name:  "auth_token_test",
			Value: firstToken,
		},
	)
	req.AddCookie(
		&http.Cookie{
			Name:  "auth_token_test",
			Value: secondToken,
		},
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	// Multiple credentials with the same authority must never produce an
	// arbitrary authenticated identity. Exact external status may depend on
	// whether ambiguity is classified as malformed credentials or invalid
	// authentication, but successful authorization is forbidden.
	if resp.StatusCode == http.StatusOK {
		t.Fatal(
			"duplicate authentication cookies selected an arbitrary credential",
		)
	}
}

func TestCredentialsAndPolicyControlHeadersTerminateAtProxyBoundary(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	baseURL := testEnv.baseURLFor(
		t,
		nginxConfigClaimExpressionHeader,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		baseURL+"/headers",
		nil,
	)
	if err != nil {
		t.Fatalf(
			"create request: %v",
			err,
		)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`subject == "camera-front"`,
	)
	req.AddCookie(
		&http.Cookie{
			Name:  "auth_token_test",
			Value: token,
		},
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"request: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(
		t,
		resp.Body,
	)

	for _, name := range []string{
		"Authorization",
		"Cookie",
		claimExpressionHeader,
	} {
		if got := headers.Get(name); got != "" {
			t.Fatalf(
				"%s leaked to protected upstream: %q",
				name,
				got,
			)
		}
	}

	if got := headers.Get("X-Auth-Subject"); got != "camera-front" {
		t.Fatalf(
			"normalized identity missing after boundary sanitization: got %q",
			got,
		)
	}
}
