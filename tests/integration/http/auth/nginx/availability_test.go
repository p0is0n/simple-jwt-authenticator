//go:build integration

package nginx_test

import (
	"context"
	"net/http"
	"testing"

	"simple-jwt-authenticator/tests/integration/support/lifecycle"
)

func TestAuthenticatorUnavailableFailsClosed(t *testing.T) {
	ctx := context.Background()

	env, err := startEnvironment(ctx)
	if err != nil {
		t.Fatalf(
			"start isolated Nginx integration environment: %v",
			err,
		)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := lifecycle.CleanupContext()
		defer cancel()

		if err := env.Close(cleanupCtx); err != nil {
			t.Errorf(
				"close isolated Nginx integration environment: %v",
				err,
			)
		}
	})

	token := env.tokens.Generate(
		t,
		"camera-front",
		"front",
		"front@example.com",
		[]string{validAudience},
		nil,
	)

	// Establish that the environment was healthy and authentication succeeded
	// before simulating the dependency outage.
	req, err := http.NewRequest(
		http.MethodGet,
		env.baseURL+"/get",
		nil,
	)
	if err != nil {
		t.Fatalf(
			"create healthy request: %v",
			err,
		)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	resp, err := env.client.Do(req)
	if err != nil {
		t.Fatalf(
			"healthy request: %v",
			err,
		)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"healthy environment: expected %d, got %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	stopCtx, cancel := lifecycle.CleanupContext()
	defer cancel()

	if err := env.authenticator.Stop(stopCtx); err != nil {
		t.Fatalf(
			"stop authenticator: %v",
			err,
		)
	}

	tests := []struct {
		name          string
		authorization string
	}{
		{
			name:          "valid-token",
			authorization: "Bearer " + token,
		},
		{
			name:          "malformed-token",
			authorization: "Bearer definitely-not-a-jwt",
		},
		{
			name:          "missing-token",
			authorization: "",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					env.baseURL+"/get",
					nil,
				)
				if err != nil {
					t.Fatalf(
						"create request: %v",
						err,
					)
				}

				if tt.authorization != "" {
					req.Header.Set(
						"Authorization",
						tt.authorization,
					)
				}

				resp, err := env.client.Do(req)
				if err != nil {
					t.Fatalf(
						"request through Nginx with unavailable authenticator: %v",
						err,
					)
				}
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusInternalServerError {
					t.Fatalf(
						"unavailable authenticator must fail closed: expected %d, got %d",
						http.StatusInternalServerError,
						resp.StatusCode,
					)
				}
			},
		)
	}
}

func TestBlankClientClaimExpressionHeaderIsTreatedAsAbsentByNginx(
	t *testing.T,
) {
	token := validClaimExpressionTestToken(t)

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
		t.Run(
			tt.name,
			func(t *testing.T) {
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

				// Assign directly so an explicitly empty value remains part
				// of the client request instead of being omitted by the test.
				req.Header[claimExpressionHeader] = []string{
					tt.value,
				}

				resp, err := testEnv.client.Do(req)
				if err != nil {
					t.Fatalf(
						"request: %v",
						err,
					)
				}
				defer func() { _ = resp.Body.Close() }()

				// The header-extractor fixture forwards the client value
				// through proxy_set_header. Blank external values become
				// indistinguishable from an absent claim-expression header at
				// the authenticator boundary.
				//
				// Direct HTTP extractor tests remain responsible for proving
				// that an explicitly received blank header is rejected as a
				// malformed expression.
				if resp.StatusCode != http.StatusOK {
					t.Fatalf(
						"blank claim-expression header: expected %d, got %d",
						http.StatusOK,
						resp.StatusCode,
					)
				}
			},
		)
	}
}
