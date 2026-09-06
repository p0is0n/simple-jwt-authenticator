//go:build integration

package nginx_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

const claimExpressionHeader = "X-Auth-Claim-Expression"

const claimExpressionQueryParameter = "claim-expression"

func TestClaimExpressionFromHeaderAllowsMatchingToken(
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

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionHeader,
		)+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`subject == "camera-front"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"matching header claim expression: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionFromHeaderBlocksNonMatchingToken(
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

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionHeader,
		)+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`subject == "camera-front"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"non-matching header claim expression: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionFromQueryAllowsMatchingToken(
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

	requestURL := withClaimExpressionQuery(
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionQuery,
		)+"/get",
		`subject == "camera-front"`,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		requestURL,
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"matching query claim expression: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionFromQueryBlocksNonMatchingToken(
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

	requestURL := withClaimExpressionQuery(
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionQuery,
		)+"/get",
		`subject == "camera-front"`,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		requestURL,
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"non-matching query claim expression: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestNestedClaimExpressionAllowsMatchingToken(
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

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionHeader,
		)+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`(subject == "camera-front" || subject == "camera-back") && audience == "internal-services"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"matching nested claim expression: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestRegexClaimExpressionAllowsMatchingToken(
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

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionHeader,
		)+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`subject ~= "^camera-[a-z]+$"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"matching regex claim expression: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestMalformedClaimExpressionFromHeaderFailsClosed(
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
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionHeader,
		)+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`subject ==`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The authenticator classifies malformed policy as 400. Nginx
	// auth_request accepts only 2xx, 401, and 403 from the authentication
	// subrequest; any other status is treated as an authentication-service
	// error and exposed to the protected client as 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf(
			"malformed header claim expression: expected fail-closed status %d, got %d",
			http.StatusInternalServerError,
			resp.StatusCode,
		)
	}
}

func TestMalformedClaimExpressionFromQueryFailsClosed(
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

	requestURL := withClaimExpressionQuery(
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionQuery,
		)+"/get",
		`subject ==`,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		requestURL,
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// A direct authenticator request receives 400. Through auth_request that
	// unsupported subrequest status becomes a fail-closed 500 response.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf(
			"malformed query claim expression: expected fail-closed status %d, got %d",
			http.StatusInternalServerError,
			resp.StatusCode,
		)
	}
}

func TestMultipleClaimExpressionSourcesFailClosed(
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

	requestURL := withClaimExpressionQuery(
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionMultiple,
		)+"/get",
		`subject == "camera-front"`,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		requestURL,
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`subject == "camera-front"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The authenticator rejects multiple policy sources as ambiguous with
	// 400. Through auth_request that unsupported authentication-subrequest
	// status becomes 500, preserving fail-closed behavior.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf(
			"claim expression from both header and query: expected fail-closed status %d, got %d",
			http.StatusInternalServerError,
			resp.StatusCode,
		)
	}
}

func TestConflictingClaimExpressionSourcesFailClosed(
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

	// The query policy matches while the header policy does not. The request
	// must still be rejected as ambiguous instead of selecting whichever
	// source happens to have precedence.
	requestURL := withClaimExpressionQuery(
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionMultiple,
		)+"/get",
		`subject == "camera-front"`,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		requestURL,
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`subject == "camera-back"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Source ambiguity is rejected before either expression can become
	// authoritative. The authenticator returns 400; Nginx auth_request maps
	// that unsupported subrequest status to a fail-closed 500 response.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf(
			"conflicting claim-expression sources: expected fail-closed status %d, got %d",
			http.StatusInternalServerError,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionCannotWeakenConfiguredAudience(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{"attacker-audience"},
		nil,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionHeader,
		)+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	// The dynamic policy deliberately accepts the token's audience. Static
	// configured audience validation must still run first and reject it.
	req.Header.Set(
		claimExpressionHeader,
		`audience == "attacker-audience"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"dynamic policy weakened configured audience: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionCanTightenConfiguredAudience(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{
			validAudience,
			"camera-services",
		},
		nil,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionHeader,
		)+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	req.Header.Set(
		claimExpressionHeader,
		`audience == "camera-services"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"additional audience policy: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestMissingClaimDoesNotSatisfyRegexExpression(
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
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionHeader,
		)+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	// A missing optional claim must not be converted into an empty string that
	// can satisfy a permissive regular expression.
	req.Header.Set(
		claimExpressionHeader,
		`email ~= ".*"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"missing claim matched regex: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionQueryIsPreservedForProtectedUpstream(
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

	expression := `subject == "camera-front"`

	requestURL := withClaimExpressionQuery(
		testEnv.baseURLFor(
			t,
			nginxConfigClaimExpressionQuery,
		)+"/get?camera=front",
		expression,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		requestURL,
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
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
		Args url.Values `json:"args"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf(
			"decode upstream response: %v",
			err,
		)
	}

	if got := body.Args.Get("camera"); got != "front" {
		t.Fatalf(
			"camera query value changed: got %q, want %q",
			got,
			"front",
		)
	}

	if got := body.Args.Get(
		claimExpressionQueryParameter,
	); got != expression {
		t.Fatalf(
			"claim-expression query value changed: got %q, want %q",
			got,
			expression,
		)
	}
}

func withClaimExpressionQuery(
	rawURL string,
	expression string,
) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}

	query := parsed.Query()
	query.Add(
		claimExpressionQueryParameter,
		expression,
	)

	parsed.RawQuery = query.Encode()

	return parsed.String()
}
