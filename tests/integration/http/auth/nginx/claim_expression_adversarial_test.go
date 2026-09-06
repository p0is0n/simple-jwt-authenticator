//go:build integration

package nginx_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDuplicateClaimExpressionHeaderValuesFailClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

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
	req.Header.Add(
		claimExpressionHeader,
		`subject == "camera-front"`,
	)
	req.Header.Add(
		claimExpressionHeader,
		`subject == "camera-front"`,
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestConflictingDuplicateClaimExpressionHeaderValuesFailClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

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
	req.Header.Add(
		claimExpressionHeader,
		`subject == "camera-front"`,
	)
	req.Header.Add(
		claimExpressionHeader,
		`subject == "camera-back"`,
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestDuplicateClaimExpressionQueryValuesFailClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	baseURL := testEnv.baseURLFor(
		t,
		nginxConfigClaimExpressionQuery,
	)

	parsed, err := url.Parse(baseURL + "/get")
	if err != nil {
		t.Fatalf(
			"parse URL: %v",
			err,
		)
	}

	query := parsed.Query()
	query.Add(
		claimExpressionQueryParameter,
		`subject == "camera-front"`,
	)
	query.Add(
		claimExpressionQueryParameter,
		`subject == "camera-front"`,
	)

	parsed.RawQuery = query.Encode()

	req, err := http.NewRequest(
		http.MethodGet,
		parsed.String(),
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

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestConflictingDuplicateClaimExpressionQueryValuesFailClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	baseURL := testEnv.baseURLFor(
		t,
		nginxConfigClaimExpressionQuery,
	)

	parsed, err := url.Parse(baseURL + "/get")
	if err != nil {
		t.Fatalf(
			"parse URL: %v",
			err,
		)
	}

	query := parsed.Query()
	query.Add(
		claimExpressionQueryParameter,
		`subject == "camera-front"`,
	)
	query.Add(
		claimExpressionQueryParameter,
		`subject == "camera-back"`,
	)

	parsed.RawQuery = query.Encode()

	req, err := http.NewRequest(
		http.MethodGet,
		parsed.String(),
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

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestBlankClaimExpressionQueryFailsClosed(
	t *testing.T,
) {
	tests := []struct {
		name  string
		value string
	}{
		{
			name:  "empty",
			value: "",
		},
		{
			name:  "space",
			value: " ",
		},
		{
			name:  "multiple-spaces",
			value: "   ",
		},
		{
			name:  "tab",
			value: "\t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := validClaimExpressionTestToken(t)

			baseURL := testEnv.baseURLFor(
				t,
				nginxConfigClaimExpressionQuery,
			)

			requestURL := withClaimExpressionQuery(
				baseURL+"/get",
				tt.value,
			)

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

			assertClaimExpressionPolicyErrorFailsClosed(
				t,
				req,
			)
		})
	}
}

func TestMalformedPercentEncodedClaimExpressionQueryFailsClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	baseURL := testEnv.baseURLFor(
		t,
		nginxConfigClaimExpressionQuery,
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

	// Assign RawQuery directly so the malformed encoding reaches Nginx
	// unchanged instead of being normalized by net/url.
	req.URL.RawQuery = "claim-expression=%ZZ"

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestInvalidRegexClaimExpressionFailsClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject ~= "["`,
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestUnsupportedClaimNameFailsClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`role == "admin"`,
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestUnsupportedClaimExpressionOperatorsFailClosed(
	t *testing.T,
) {
	tests := []string{
		`subject != "camera-front"`,
		`subject = "camera-front"`,
		`subject === "camera-front"`,
		`subject ~ "camera-front"`,
	}

	for _, expression := range tests {
		t.Run(expression, func(t *testing.T) {
			token := validClaimExpressionTestToken(t)

			req := newHeaderClaimExpressionRequest(
				t,
				token,
				expression,
			)

			assertClaimExpressionPolicyErrorFailsClosed(
				t,
				req,
			)
		})
	}
}

func TestOversizedClaimExpressionValueFailsClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	expression := `subject == "` +
		strings.Repeat("a", 4096) +
		`"`

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		expression,
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestClaimExpressionMaximumParenthesisDepthIsAccepted(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	// The parser allows nesting up to and including 64 parenthesis levels.
	// Parentheses only control grouping and do not themselves increase the
	// depth of the constructed claim-expression AST.
	expression := strings.Repeat("(", 64) +
		`subject == "camera-front"` +
		strings.Repeat(")", 64)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		expression,
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
			"maximum supported parenthesis depth: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestExcessiveClaimExpressionParenthesisDepthFailsClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	// The parser accepts at most 64 nested parenthesis levels. Crossing that
	// boundary must be rejected before authentication rather than allowing an
	// attacker to consume unbounded recursive parser resources.
	expression := strings.Repeat("(", 65) +
		`subject == "camera-front"` +
		strings.Repeat(")", 65)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		expression,
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestExcessiveClaimExpressionASTDepthFailsClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	// Parentheses alone do not increase expression-tree depth. Construct
	// genuinely nested logical expressions instead:
	//
	//	(
	//	    (
	//	        subject == "camera-front"
	//	        && subject == "camera-front"
	//	    )
	//	    && subject == "camera-front"
	//	)
	//
	// Each wrapper creates another logical AST node. The claim package limits
	// expression depth to 16, so enough nested logical groups must eventually
	// be rejected even though every individual comparison is valid.
	expression := `subject == "camera-front"`

	for range 16 {
		expression = "(" +
			expression +
			` && subject == "camera-front")`
	}

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		expression,
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestExcessiveClaimExpressionNodeCountFailsClosed(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	parts := make(
		[]string,
		128,
	)

	for index := range parts {
		parts[index] = `subject == "camera-front"`
	}

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		strings.Join(
			parts,
			" && ",
		),
	)

	assertClaimExpressionPolicyErrorFailsClosed(
		t,
		req,
	)
}

func TestClaimExpressionAndRequiresEveryCondition(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject == "camera-front" && email == "other@example.com"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"failed AND branch must reject request: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionOrAllowsSecondMatchingBranch(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject == "camera-back" || subject == "camera-front"`,
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
			"second OR branch must authorize request: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionOrRejectsWhenEveryBranchFails(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject == "camera-left" || subject == "camera-right"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"failed OR expression must reject request: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionAndHasHigherPrecedenceThanOr(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"wrong@example.com",
		[]string{validAudience},
		nil,
	)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject == "camera-front" || subject == "camera-back" && email == "front@example.com"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	// Correct precedence is:
	//
	//	subject == camera-front ||
	//	(subject == camera-back && email == front@example.com)
	//
	// The first branch is true, so the entire expression is true.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"operator precedence changed: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionParenthesesOverrideDefaultPrecedence(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"wrong@example.com",
		[]string{validAudience},
		nil,
	)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`(subject == "camera-front" || subject == "camera-back") && email == "front@example.com"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"parenthesized expression must reject request: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestAudienceExpressionMatchesAnyAudienceElement(
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

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`audience == "camera-services"`,
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
			"second audience value must match: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestAudienceRegexMatchesAnyAudienceElement(
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

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`audience ~= "^camera-"`,
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
			"audience regex must match second element: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionEqualityIsCaseSensitive(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject == "Camera-Front"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"case-insensitive equality detected: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionEqualityDoesNotTrimClaimValue(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject == "camera-front "`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"trimmed equality detected: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionRegexUsesSearchSemantics(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"super-admin",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject ~= "admin"`,
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
			"unanchored regex must use search semantics: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestClaimExpressionAnchoredRegexRequiresFullMatch(
	t *testing.T,
) {
	token := testEnv.tokens.Generate(
		t,
		"super-admin",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`subject ~= "^admin$"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"anchored regex unexpectedly matched: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func TestMissingClaimDoesNotMatchEmptyStringRegex(
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

	req := newHeaderClaimExpressionRequest(
		t,
		token,
		`email ~= "^$"`,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf(
			"missing claim was treated as empty string: expected %d, got %d",
			http.StatusUnauthorized,
			resp.StatusCode,
		)
	}
}

func validClaimExpressionTestToken(
	t testing.TB,
) string {
	t.Helper()

	return testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)
}

func newHeaderClaimExpressionRequest(
	t testing.TB,
	token string,
	expression string,
) *http.Request {
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

	return req
}

func assertClaimExpressionPolicyErrorFailsClosed(
	t testing.TB,
	req *http.Request,
) {
	t.Helper()

	resp, err := testEnv.client.Do(req)
	if err != nil {
		t.Fatalf(
			"request: %v",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	// Malformed/ambiguous policy is a 400 at the authenticator boundary.
	// Nginx auth_request only understands 2xx, 401, and 403. Any other
	// authentication-subrequest result therefore fails closed as 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf(
			"policy error must fail closed through Nginx: expected %d, got %d",
			http.StatusInternalServerError,
			resp.StatusCode,
		)
	}
}
