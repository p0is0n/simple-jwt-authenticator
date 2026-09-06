//go:build integration

package nginx_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestInternalAuthEndpointIsInaccessibleInEveryFixture(
	t *testing.T,
) {
	for _, config := range nginxConfigs {
		t.Run(
			string(config),
			func(t *testing.T) {
				baseURL := testEnv.baseURLFor(
					t,
					config,
				)

				for _, method := range []string{
					http.MethodGet,
					http.MethodPost,
				} {
					req, err := http.NewRequest(
						method,
						baseURL+
							"/_auth?claim-expression=subject%20%3D%3D%20%22camera-front%22",
						nil,
					)
					if err != nil {
						t.Fatalf(
							"create request: %v",
							err,
						)
					}

					resp, err := testEnv.client.Do(req)
					if err != nil {
						t.Fatalf(
							"request: %v",
							err,
						)
					}
					defer func() { _ = resp.Body.Close() }()

					if resp.StatusCode != http.StatusNotFound {
						t.Fatalf(
							"%s /_auth via %s: expected %d, got %d",
							config,
							method,
							http.StatusNotFound,
							resp.StatusCode,
						)
					}
				}
			},
		)
	}
}

func TestHealthEndpointRemainsIndependentOfAuthenticationInput(
	t *testing.T,
) {
	for _, config := range nginxConfigs {
		t.Run(
			string(config),
			func(t *testing.T) {
				baseURL := testEnv.baseURLFor(
					t,
					config,
				)

				req, err := http.NewRequest(
					http.MethodGet,
					baseURL+"/_health",
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
					"Bearer definitely-not-a-jwt",
				)
				req.Header.Set(
					claimExpressionHeader,
					`definitely invalid`,
				)
				req.Header.Set(
					"X-Auth-Subject",
					"attacker",
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
						"health endpoint for %s: expected %d, got %d",
						config,
						http.StatusOK,
						resp.StatusCode,
					)
				}
			},
		)
	}
}

func TestProtectedRequestBodyPreservedAcrossBufferBoundaries(
	t *testing.T,
) {
	sizes := []int{
		1,
		8191,
		8192,
		8193,
		64 * 1024,
		256 * 1024,
	}

	token := testEnv.tokens.Generate(
		t,
		"camera-front",
		"",
		"",
		[]string{validAudience},
		nil,
	)

	for _, size := range sizes {
		t.Run(
			fmt.Sprintf("%d-bytes", size),
			func(t *testing.T) {
				payload := bytes.Repeat(
					[]byte("x"),
					size,
				)

				wantHash := sha256.Sum256(payload)

				req, err := http.NewRequest(
					http.MethodPost,
					testEnv.baseURL+"/anything",
					bytes.NewReader(payload),
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
					"Content-Type",
					"text/plain; charset=utf-8",
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
						"expected %d, got %d",
						http.StatusOK,
						resp.StatusCode,
					)
				}

				var body struct {
					Data string `json:"data"`
				}

				if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
					t.Fatalf(
						"decode upstream response: %v",
						err,
					)
				}

				gotHash := sha256.Sum256(
					[]byte(body.Data),
				)

				if gotHash != wantHash {
					t.Fatalf(
						"body changed after auth_request: expected %d bytes with SHA-256 %x, got %d bytes with SHA-256 %x",
						len(payload),
						wantHash,
						len(body.Data),
						gotHash,
					)
				}
			},
		)
	}
}

func TestProtectedQueryEncodingSemanticsPreserved(
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

	requestURL := testEnv.baseURL +
		"/get?a=1&a=2&empty=&space=hello%20world&plus=a%2Bb&unicode=%D1%82%D0%B5%D1%81%D1%82"

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

	if got := body.Args["a"]; len(got) != 2 ||
		got[0] != "1" ||
		got[1] != "2" {
		t.Fatalf(
			"duplicate query values changed: %#v",
			got,
		)
	}

	if got := body.Args.Get("empty"); got != "" {
		t.Fatalf(
			"empty query value changed: %q",
			got,
		)
	}

	if got := body.Args.Get("space"); got != "hello world" {
		t.Fatalf(
			"encoded space changed: %q",
			got,
		)
	}

	if got := body.Args.Get("plus"); got != "a+b" {
		t.Fatalf(
			"encoded plus changed: %q",
			got,
		)
	}

	if got := body.Args.Get("unicode"); got != "тест" {
		t.Fatalf(
			"Unicode query changed: %q",
			got,
		)
	}
}

func TestUnsafeIdentityClaimCannotReachProtectedUpstream(
	t *testing.T,
) {
	tests := []struct {
		name    string
		subject string
	}{
		{
			name:    "carriage-return",
			subject: "camera\rattacker",
		},
		{
			name:    "line-feed",
			subject: "camera\nattacker",
		},
		{
			name:    "tab",
			subject: "camera\tattacker",
		},
		{
			name:    "delete",
			subject: "camera\x7fattacker",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				token := testEnv.tokens.Generate(
					t,
					tt.subject,
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

				if resp.StatusCode == http.StatusOK {
					t.Fatalf(
						"unsafe identity subject %q reached protected upstream",
						tt.subject,
					)
				}

				for _, name := range []string{
					"X-Auth-Subject",
					"X-Auth-Username",
					"X-Auth-Email",
				} {
					if got := resp.Header.Get(name); got != "" {
						t.Fatalf(
							"rejected response leaked %s=%q",
							name,
							got,
						)
					}
				}
			},
		)
	}
}
