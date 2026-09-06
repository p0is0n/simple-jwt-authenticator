package extractor

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"simple-jwt-authenticator/internal/transport/http/credential"
)

func TestAuthorizationHeader_AbsentNotApplicable(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	result, err := AuthorizationHeader{}.Extract(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Extracted {
		t.Fatal("expected credential not to be extracted")
	}

	if !result.NotApplicable {
		t.Fatal("expected extractor to be not applicable")
	}

	if result.Source != credential.SourceAuthorizationHeader {
		t.Fatalf(
			"unexpected source: got %q, want %q",
			result.Source,
			credential.SourceAuthorizationHeader,
		)
	}
}

func TestAuthorizationHeader_ValidBearerExtracted(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(
		"Authorization",
		"Bearer eyJhbGciOiJub25lIn0",
	)

	result, err := AuthorizationHeader{}.Extract(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Extracted {
		t.Fatal("expected credential to be extracted")
	}

	if result.NotApplicable {
		t.Fatal("extracted credential must not be not applicable")
	}

	if result.Source != credential.SourceAuthorizationHeader {
		t.Fatalf(
			"unexpected source: got %q, want %q",
			result.Source,
			credential.SourceAuthorizationHeader,
		)
	}

	if result.Credential.Value != "eyJhbGciOiJub25lIn0" {
		t.Fatalf(
			"unexpected credential value: got %q",
			result.Credential.Value,
		)
	}
}

func TestAuthorizationHeader_DuplicateHeadersFound(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(
		"Authorization",
		"Bearer eyJhbGciOiJub25lIn0",
	)
	request.Header.Add(
		"Authorization",
		"Bearer ecDhbdjsk4jfJd25lIf4",
	)

	_, err := AuthorizationHeader{}.Extract(request)
	if !errors.Is(err, credential.ErrMalformedCredential) {
		t.Fatalf(
			"expected ErrMalformedCredential, got %v",
			err,
		)
	}
}

func TestAuthorizationHeader_SchemeIsCaseInsensitive(t *testing.T) {
	tests := []string{
		"Bearer token",
		"bearer token",
		"BEARER token",
	}

	for _, header := range tests {
		t.Run(header, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", header)

			result, err := AuthorizationHeader{}.Extract(request)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if !result.Extracted {
				t.Fatal("expected credential to be extracted")
			}

			if result.Credential.Value != "token" {
				t.Fatalf(
					"unexpected credential value: got %q, want %q",
					result.Credential.Value,
					"token",
				)
			}
		})
	}
}

func TestAuthorizationHeader_TrimsBearerValue(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer    token   ")

	result, err := AuthorizationHeader{}.Extract(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Credential.Value != "token" {
		t.Fatalf(
			"unexpected credential value: got %q, want %q",
			result.Credential.Value,
			"token",
		)
	}
}

func TestAuthorizationHeader_NonBearerSchemeTerminalError(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	result, err := AuthorizationHeader{}.Extract(request)

	if !errors.Is(err, credential.ErrMalformedCredential) {
		t.Fatalf(
			"expected ErrMalformedCredential, got %v",
			err,
		)
	}

	if result.Source != credential.SourceAuthorizationHeader {
		t.Fatalf(
			"unexpected source: got %q, want %q",
			result.Source,
			credential.SourceAuthorizationHeader,
		)
	}

	if result.Extracted {
		t.Fatal("malformed credential must not be extracted")
	}
}

func TestAuthorizationHeader_MissingTokenTerminalError(t *testing.T) {
	tests := []string{
		"Bearer",
		"Bearer ",
		"Bearer    ",
	}

	for _, header := range tests {
		t.Run(header, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", header)

			result, err := AuthorizationHeader{}.Extract(request)

			if !errors.Is(err, credential.ErrMalformedCredential) {
				t.Fatalf(
					"expected ErrMalformedCredential, got %v",
					err,
				)
			}

			if result.Source != credential.SourceAuthorizationHeader {
				t.Fatalf(
					"unexpected source: got %q, want %q",
					result.Source,
					credential.SourceAuthorizationHeader,
				)
			}
		})
	}
}
