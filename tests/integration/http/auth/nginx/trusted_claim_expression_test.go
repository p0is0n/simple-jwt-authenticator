//go:build integration

package nginx_test

import (
	"net/http"
	"testing"

	"simple-jwt-authenticator/tests/integration/support/authenticator"
)

func TestTrustedClaimExpressionAllowsMatchingToken(
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

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		"",
		"",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"matching trusted claim expression: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestTrustedClaimExpressionBlocksNonMatchingToken(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-back",
		"back",
		"back@example.com",
		[]string{validAudience},
		nil,
	)

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		"",
		"",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"non-matching trusted claim expression: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

// The client deliberately supplies a policy authorizing its own token.
//
// If this test ever becomes 200, the trusted authorization boundary has been
// broken: an external caller can replace the route policy owned by Nginx.
func TestClientCannotOverrideTrustedClaimExpression(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-back",
		"back",
		"back@example.com",
		[]string{validAudience},
		nil,
	)

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		`subject == "camera-back"`,
		"",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"client override of trusted policy: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

// External policy has no authority on a trusted-policy route, even when it
// would make authorization stricter.
func TestClientCannotTightenTrustedClaimExpression(
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

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		`subject == "camera-back"`,
		"",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"client policy influenced trusted policy: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

// Malformed external policy must never reach the policy parser when Nginx
// owns the route policy.
func TestMalformedClientClaimExpressionCannotBreakTrustedPolicy(
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

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		`subject ==`,
		"",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"malformed client header policy influenced trusted route: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestClientQueryClaimExpressionCannotOverrideTrustedPolicy(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-back",
		"back",
		"back@example.com",
		[]string{validAudience},
		nil,
	)

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		"",
		`subject == "camera-back"`,
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"client query policy overrode trusted policy: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestMalformedClientQueryCannotBreakTrustedPolicy(
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

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		"",
		`subject ==`,
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"malformed client query policy influenced trusted route: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestMultipleClientClaimExpressionSourcesCannotBreakTrustedPolicy(
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

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		`subject == "header-attacker"`,
		`subject == "query-attacker"`,
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"untrusted source ambiguity influenced trusted route: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestTrustedClaimExpressionCannotWeakenConfiguredAudience(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{"attacker-audience"},
		nil,
	)

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		"",
		"",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"trusted policy weakened configured audience: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestTrustedClaimExpressionCannotWeakenConfiguredIssuer(
	t *testing.T,
) {
	builder, err := authenticator.NewTokenBuilder(
		testEnv.keys.PrivateKey,
		"attacker-issuer",
	)
	if err != nil {
		t.Fatalf(
			"create alternate issuer token builder: %v",
			err,
		)
	}

	token := builder.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		"",
		"",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"trusted policy weakened configured issuer: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestTrustedClaimExpressionCannotWeakenSignatureValidation(
	t *testing.T,
) {
	otherKeys, err := authenticator.GenerateKeyPair(
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf(
			"generate alternate key pair: %v",
			err,
		)
	}

	builder, err := authenticator.NewTokenBuilder(
		otherKeys.PrivateKey,
		authenticator.DefaultIssuer,
	)
	if err != nil {
		t.Fatalf(
			"create alternate signing token builder: %v",
			err,
		)
	}

	token := builder.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	resp := requestThroughTrustedClaimExpressionFixture(
		t,
		token,
		"",
		"",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"trusted policy weakened signature validation: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestTrustedClaimExpressionHeaderDoesNotReachProtectedUpstream(
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
		nginxConfigClaimExpressionTrusted,
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
		`subject == "CLIENT-POLICY-MUST-NOT-LEAK"`,
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
			"trusted policy request: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(
		t,
		resp.Body,
	)

	if got := headers.Get(claimExpressionHeader); got != "" {
		t.Fatalf(
			"claim-expression policy leaked to protected upstream: %q",
			got,
		)
	}
}

func TestTrustedClaimExpressionPropagatesOnlyAuthenticatedIdentity(
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
		nginxConfigClaimExpressionTrusted,
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
		"X-Auth-Subject",
		"attacker",
	)
	req.Header.Set(
		"X-Auth-Username",
		"attacker",
	)
	req.Header.Set(
		"X-Auth-Email",
		"attacker@example.com",
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
			"trusted policy request: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	headers := decodeUpstreamHeaders(
		t,
		resp.Body,
	)

	if got := headers.Get("X-Auth-Subject"); got != "camera-front" {
		t.Fatalf(
			"subject mismatch: got %q, want %q",
			got,
			"camera-front",
		)
	}

	if got := headers.Get("X-Auth-Username"); got != "front" {
		t.Fatalf(
			"username mismatch: got %q, want %q",
			got,
			"front",
		)
	}

	if got := headers.Get("X-Auth-Email"); got != "front@example.com" {
		t.Fatalf(
			"email mismatch: got %q, want %q",
			got,
			"front@example.com",
		)
	}

	if got := headers.Get("Authorization"); got != "" {
		t.Fatalf(
			"Authorization leaked to protected upstream: %q",
			got,
		)
	}

	if got := headers.Get("Cookie"); got != "" {
		t.Fatalf(
			"Cookie leaked to protected upstream: %q",
			got,
		)
	}

	if got := headers.Get(claimExpressionHeader); got != "" {
		t.Fatalf(
			"claim-expression policy leaked to protected upstream: %q",
			got,
		)
	}
}

func requestThroughTrustedClaimExpressionFixture(
	t testing.TB,
	token string,
	clientHeaderExpression string,
	clientQueryExpression string,
) *http.Response {
	t.Helper()

	baseURL := testEnv.baseURLFor(
		t,
		nginxConfigClaimExpressionTrusted,
	)

	requestURL := baseURL + "/get"

	if clientQueryExpression != "" {
		requestURL = withClaimExpressionQuery(
			requestURL,
			clientQueryExpression,
		)
	}

	req, err := http.NewRequest(
		http.MethodGet,
		requestURL,
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

	if clientHeaderExpression != "" {
		req.Header.Set(
			claimExpressionHeader,
			clientHeaderExpression,
		)
	}

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}

	return resp
}
