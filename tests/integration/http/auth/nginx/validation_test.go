//go:build integration

package nginx_test

import (
	"net/http"
	"testing"

	"simple-jwt-authenticator/tests/integration/support/authenticator"
)

func TestExpiredTokenBlocked(t *testing.T) {
	token := testEnv.tokens.GenerateExpired(
		t,
		"camera-front",
		[]string{validAudience},
	)

	resp := requestWithBearerToken(t, token)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"expired token: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestInvalidSignatureBlocked(t *testing.T) {
	otherKeys, err := authenticator.GenerateKeyPair(t.TempDir())
	if err != nil {
		t.Fatalf(
			"generate alternate signing key: %v",
			err,
		)
	}

	otherBuilder, err := authenticator.NewTokenBuilder(
		otherKeys.PrivateKey,
		authenticator.DefaultIssuer,
	)
	if err != nil {
		t.Fatalf(
			"create token builder: %v",
			err,
		)
	}

	token := otherBuilder.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	resp := requestWithBearerToken(t, token)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"invalid signature: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestIssuerMismatchBlocked(t *testing.T) {
	builder, err := authenticator.NewTokenBuilder(
		testEnv.keys.PrivateKey,
		"wrong-issuer",
	)
	if err != nil {
		t.Fatalf(
			"create token builder: %v",
			err,
		)
	}

	token := builder.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	resp := requestWithBearerToken(t, token)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"issuer mismatch: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestAudienceMismatchBlocked(t *testing.T) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{"wrong-audience"},
		nil,
	)

	resp := requestWithBearerToken(t, token)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"audience mismatch: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestMatchingDynamicPolicyCannotBypassExpiredToken(
	t *testing.T,
) {
	token := testEnv.tokens.GenerateExpired(
		t,
		"camera-front",
		[]string{validAudience},
	)

	resp := requestWithHeaderClaimExpression(
		t,
		token,
		`subject == "camera-front"`,
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"dynamic policy bypassed expiration validation: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestMatchingDynamicPolicyCannotBypassIssuerValidation(
	t *testing.T,
) {
	builder, err := authenticator.NewTokenBuilder(
		testEnv.keys.PrivateKey,
		"wrong-issuer",
	)
	if err != nil {
		t.Fatalf(
			"create token builder: %v",
			err,
		)
	}

	token := builder.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	resp := requestWithHeaderClaimExpression(
		t,
		token,
		`subject == "camera-front"`,
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"dynamic policy bypassed issuer validation: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestMatchingDynamicPolicyCannotBypassSignatureValidation(
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
			"create token builder: %v",
			err,
		)
	}

	token := builder.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	resp := requestWithHeaderClaimExpression(
		t,
		token,
		`subject == "camera-front"`,
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"dynamic policy bypassed signature validation: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestAuthenticationResultDoesNotLeakBetweenRequests(t *testing.T) {
	validToken := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	resp := requestWithBearerToken(t, validToken)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"first valid request: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	resp = requestWithBearerToken(
		t,
		"definitely-not-a-jwt",
	)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"invalid request after valid request: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}

	resp = requestWithBearerToken(t, validToken)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"valid request after invalid request: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func requestWithBearerToken(
	t testing.TB,
	token string,
) *http.Response {
	t.Helper()

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

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}

	return resp
}

func requestWithHeaderClaimExpression(
	t testing.TB,
	token string,
	expression string,
) *http.Response {
	t.Helper()

	baseURL := testEnv.baseURLFor(
		t,
		nginxConfigClaimExpressionHeader,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		baseURL+"/get",
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
		expression,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}

	return resp
}
