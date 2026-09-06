//go:build integration

package nginx_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestDefaultRouteIgnoresClientClaimExpressionHeader(
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
	req.Header.Set(
		claimExpressionHeader,
		`subject == "attacker"`,
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
			"client policy affected default route: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestDefaultRouteIgnoresMalformedClientClaimExpressionHeader(
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
	req.Header.Set(
		claimExpressionHeader,
		`definitely not valid policy`,
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
			"malformed client policy affected default route: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestDefaultRouteIgnoresClientClaimExpressionQuery(
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
		testEnv.baseURL+"/get",
		`subject == "attacker"`,
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
			"client query policy affected default route: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestDefaultRouteIgnoresSimultaneousClientPolicySources(
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
		testEnv.baseURL+"/get",
		`subject == "query-attacker"`,
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
	req.Header.Set(
		claimExpressionHeader,
		`subject == "header-attacker"`,
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
			"client policy source ambiguity affected default route: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}
}

func TestDefaultRoutePreservesClaimExpressionAsApplicationQuery(
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

	expression := `subject == "application-data"`

	requestURL := withClaimExpressionQuery(
		testEnv.baseURL+
			"/get?camera=front&access_token=SENSITIVE-MARKER",
		expression,
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
			"default query request: expected %d, got %d",
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
			"camera query changed: got %q, want %q",
			got,
			"front",
		)
	}

	if got := body.Args.Get("access_token"); got != "SENSITIVE-MARKER" {
		t.Fatalf(
			"application query changed: got %q",
			got,
		)
	}

	if got := body.Args.Get(
		claimExpressionQueryParameter,
	); got != expression {
		t.Fatalf(
			"claim-expression application query changed: got %q, want %q",
			got,
			expression,
		)
	}
}
