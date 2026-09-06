//go:build integration

package nginx_test

import (
	"net/http"
	"sync"
	"testing"
)

func TestClaimExpressionDoesNotLeakBetweenSequentialRequests(
	t *testing.T,
) {
	cameraFront := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	cameraBack := testEnv.tokens.Generate(
		t,
		"camera-back",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	baseURL := testEnv.baseURLFor(
		t,
		nginxConfigClaimExpressionHeader,
	)

	tests := []struct {
		name       string
		token      string
		expression string
		wantStatus int
	}{
		{
			name:       "front-with-front-policy",
			token:      cameraFront,
			expression: `subject == "camera-front"`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "back-with-front-policy",
			token:      cameraBack,
			expression: `subject == "camera-front"`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "back-with-back-policy",
			token:      cameraBack,
			expression: `subject == "camera-back"`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "front-with-back-policy",
			token:      cameraFront,
			expression: `subject == "camera-back"`,
			wantStatus: http.StatusUnauthorized,
		},
	}

	for iteration := range 10 {
		for _, tt := range tests {
			t.Run(
				tt.name,
				func(t *testing.T) {
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
						"Bearer "+tt.token,
					)
					req.Header.Set(
						claimExpressionHeader,
						tt.expression,
					)

					resp, err := testEnv.client.Do(req)
					if err != nil {
						t.Fatalf(
							"iteration %d request: %v",
							iteration,
							err,
						)
					}
					defer func() { _ = resp.Body.Close() }()

					if resp.StatusCode != tt.wantStatus {
						t.Fatalf(
							"iteration %d: expected %d, got %d",
							iteration,
							tt.wantStatus,
							resp.StatusCode,
						)
					}
				},
			)
		}
	}
}

func TestConcurrentClaimExpressionsDoNotLeakBetweenRequests(
	t *testing.T,
) {
	const requestsPerScenario = 50

	type scenario struct {
		name       string
		subject    string
		expression string
		wantStatus int
	}

	scenarios := []scenario{
		{
			name:       "front-match",
			subject:    "camera-front",
			expression: `subject == "camera-front"`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "back-match",
			subject:    "camera-back",
			expression: `subject == "camera-back"`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "front-mismatch",
			subject:    "camera-front",
			expression: `subject == "camera-back"`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "back-mismatch",
			subject:    "camera-back",
			expression: `subject == "camera-front"`,
			wantStatus: http.StatusUnauthorized,
		},
	}

	type preparedScenario struct {
		scenario
		token string
	}

	prepared := make(
		[]preparedScenario,
		0,
		len(scenarios),
	)

	for _, scenario := range scenarios {
		prepared = append(
			prepared,
			preparedScenario{
				scenario: scenario,
				token: testEnv.tokens.Generate(
					t,
					scenario.subject,
					"",
					"",
					[]string{validAudience},
					nil,
				),
			},
		)
	}

	type result struct {
		scenario preparedScenario
		status   int
		err      error
	}

	results := make(
		chan result,
		len(prepared)*requestsPerScenario,
	)

	baseURL := testEnv.baseURLFor(
		t,
		nginxConfigClaimExpressionHeader,
	)

	var waitGroup sync.WaitGroup

	for _, scenario := range prepared {
		for range requestsPerScenario {
			waitGroup.Add(1)

			go func(scenario preparedScenario) {
				defer waitGroup.Done()

				req, err := http.NewRequest(
					http.MethodGet,
					baseURL+"/get",
					nil,
				)
				if err != nil {
					results <- result{
						scenario: scenario,
						err:      err,
					}

					return
				}

				req.Header.Set(
					"Authorization",
					"Bearer "+scenario.token,
				)
				req.Header.Set(
					claimExpressionHeader,
					scenario.expression,
				)

				resp, err := testEnv.client.Do(req)
				if err != nil {
					results <- result{
						scenario: scenario,
						err:      err,
					}

					return
				}
				defer func() { _ = resp.Body.Close() }()

				results <- result{
					scenario: scenario,
					status:   resp.StatusCode,
				}
			}(scenario)
		}
	}

	waitGroup.Wait()
	close(results)

	for result := range results {
		if result.err != nil {
			t.Errorf(
				"%s request: %v",
				result.scenario.name,
				result.err,
			)

			continue
		}

		if result.status != result.scenario.wantStatus {
			t.Errorf(
				"%s policy cross-contamination: expected %d, got %d",
				result.scenario.name,
				result.scenario.wantStatus,
				result.status,
			)
		}
	}
}
