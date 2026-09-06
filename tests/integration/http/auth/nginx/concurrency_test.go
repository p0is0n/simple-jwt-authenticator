//go:build integration

package nginx_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
)

func TestIdentityDoesNotLeakBetweenSuccessfulRequests(t *testing.T) {
	firstToken := testEnv.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	secondToken := testEnv.tokens.Generate(
		t,
		"camera-back",
		"back",
		"back@example.com",
		[]string{validAudience},
		nil,
	)

	tests := []struct {
		name     string
		token    string
		subject  string
		username string
		email    string
	}{
		{
			name:     "first",
			token:    firstToken,
			subject:  "camera-front",
			username: "front",
			email:    "front@example.com",
		},
		{
			name:     "second",
			token:    secondToken,
			subject:  "camera-back",
			username: "back",
			email:    "back@example.com",
		},
		{
			name:     "first-again",
			token:    firstToken,
			subject:  "camera-front",
			username: "front",
			email:    "front@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := requestUpstreamHeaders(
				t,
				tt.token,
			)

			if got := headers.Get("X-Auth-Subject"); got != tt.subject {
				t.Fatalf(
					"expected subject %q, got %q",
					tt.subject,
					got,
				)
			}

			if got := headers.Get("X-Auth-Username"); got != tt.username {
				t.Fatalf(
					"expected username %q, got %q",
					tt.username,
					got,
				)
			}

			if got := headers.Get("X-Auth-Email"); got != tt.email {
				t.Fatalf(
					"expected email %q, got %q",
					tt.email,
					got,
				)
			}
		})
	}
}

func TestConcurrentAuthenticationResultsDoNotLeakBetweenRequests(
	t *testing.T,
) {
	const (
		identityCount       = 8
		requestsPerIdentity = 20
	)

	type identity struct {
		token    string
		subject  string
		username string
		email    string
	}

	identities := make(
		[]identity,
		0,
		identityCount,
	)

	for index := range identityCount {
		subject := fmt.Sprintf(
			"camera-%d",
			index,
		)
		username := fmt.Sprintf(
			"user-%d",
			index,
		)
		email := fmt.Sprintf(
			"user-%d@example.com",
			index,
		)

		identities = append(
			identities,
			identity{
				token: testEnv.tokens.Generate(
					t,
					subject,
					username,
					email,
					[]string{validAudience},
					nil,
				),
				subject:  subject,
				username: username,
				email:    email,
			},
		)
	}

	type result struct {
		identity identity
		headers  http.Header
		err      error
	}

	totalRequests := len(identities) * requestsPerIdentity

	results := make(
		chan result,
		totalRequests,
	)

	var waitGroup sync.WaitGroup

	for _, idnt := range identities {
		for range requestsPerIdentity {
			waitGroup.Add(1)

			go func(i identity) {
				defer waitGroup.Done()

				headers, err := fetchUpstreamHeaders(
					i.token,
				)

				results <- result{
					identity: i,
					headers:  headers,
					err:      err,
				}
			}(idnt)
		}
	}

	waitGroup.Wait()
	close(results)

	for result := range results {
		if result.err != nil {
			t.Errorf(
				"request for subject %q: %v",
				result.identity.subject,
				result.err,
			)

			continue
		}

		if got := result.headers.Get("X-Auth-Subject"); got != result.identity.subject {
			t.Errorf(
				"identity cross-contamination: expected subject %q, got %q",
				result.identity.subject,
				got,
			)
		}

		if got := result.headers.Get("X-Auth-Username"); got != result.identity.username {
			t.Errorf(
				"identity cross-contamination: expected username %q, got %q",
				result.identity.username,
				got,
			)
		}

		if got := result.headers.Get("X-Auth-Email"); got != result.identity.email {
			t.Errorf(
				"identity cross-contamination: expected email %q, got %q",
				result.identity.email,
				got,
			)
		}
	}
}

func requestUpstreamHeaders(
	t testing.TB,
	token string,
) http.Header {
	t.Helper()

	headers, err := fetchUpstreamHeaders(token)
	if err != nil {
		t.Fatalf("request upstream headers: %v", err)
	}

	return headers
}

func fetchUpstreamHeaders(
	token string,
) (http.Header, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		testEnv.baseURL+"/headers",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create request: %w",
			err,
		)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	resp, err := testEnv.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(
			"request: %w",
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"unexpected response status: got %d, want %d",
			resp.StatusCode,
			http.StatusOK,
		)
	}

	var body struct {
		Headers http.Header `json:"headers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf(
			"decode upstream headers: %w",
			err,
		)
	}

	return body.Headers, nil
}
