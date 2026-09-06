package extractor

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"simple-jwt-authenticator/internal/transport/http/credential"
)

func TestNewCookie_EmptyNameRejected(t *testing.T) {
	tests := []string{
		"",
		"   ",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewCookie(name)
			if err == nil {
				t.Fatal("expected error for empty cookie name")
			}
		})
	}
}

func TestNewCookie_TrimsName(t *testing.T) {
	extractor, err := NewCookie("  auth_token  ")
	if err != nil {
		t.Fatalf("create cookie extractor: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: "token",
	})

	result, err := extractor.Extract(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Extracted {
		t.Fatal("expected credential to be extracted")
	}
}

func TestNewCookie_DuplicateCookiesFound(t *testing.T) {
	extractor, err := NewCookie("auth_token")
	if err != nil {
		t.Fatalf("create cookie extractor: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: "token1",
	})
	request.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: "token2",
	})

	_, err = extractor.Extract(request)
	if !errors.Is(err, credential.ErrMalformedCredential) {
		t.Fatalf(
			"expected ErrMalformedCredential, got %v",
			err,
		)
	}
}

func TestCookie_AbsentNotApplicable(t *testing.T) {
	extractor, err := NewCookie("auth_token")
	if err != nil {
		t.Fatalf("create cookie extractor: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)

	result, err := extractor.Extract(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Extracted {
		t.Fatal("expected credential not to be extracted")
	}

	if !result.NotApplicable {
		t.Fatal("expected extractor to be not applicable")
	}

	if result.Source != credential.SourceCookie {
		t.Fatalf(
			"unexpected source: got %q, want %q",
			result.Source,
			credential.SourceCookie,
		)
	}
}

func TestCookie_PresentExtracted(t *testing.T) {
	extractor, err := NewCookie("auth_token")
	if err != nil {
		t.Fatalf("create cookie extractor: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: "eyJhbGciOiJub25lIn0",
	})

	result, err := extractor.Extract(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Extracted {
		t.Fatal("expected credential to be extracted")
	}

	if result.NotApplicable {
		t.Fatal("extracted credential must not be not applicable")
	}

	if result.Source != credential.SourceCookie {
		t.Fatalf(
			"unexpected source: got %q, want %q",
			result.Source,
			credential.SourceCookie,
		)
	}

	if result.Credential.Value != "eyJhbGciOiJub25lIn0" {
		t.Fatalf(
			"unexpected credential value: got %q",
			result.Credential.Value,
		)
	}
}

func TestCookie_TrimsValue(t *testing.T) {
	extractor, err := NewCookie("auth_token")
	if err != nil {
		t.Fatalf("create cookie extractor: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: "  token  ",
	})

	result, err := extractor.Extract(request)
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

func TestCookie_EmptyValueTerminalError(t *testing.T) {
	extractor, err := NewCookie("auth_token")
	if err != nil {
		t.Fatalf("create cookie extractor: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: "",
	})

	result, err := extractor.Extract(request)

	if !errors.Is(err, credential.ErrMalformedCredential) {
		t.Fatalf(
			"expected ErrMalformedCredential, got %v",
			err,
		)
	}

	if result.Source != credential.SourceCookie {
		t.Fatalf(
			"unexpected source: got %q, want %q",
			result.Source,
			credential.SourceCookie,
		)
	}

	if result.Extracted {
		t.Fatal("malformed credential must not be extracted")
	}
}

func TestCookie_WhitespaceOnlyValueTerminalError(t *testing.T) {
	extractor, err := NewCookie("auth_token")
	if err != nil {
		t.Fatalf("create cookie extractor: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: "   ",
	})

	_, err = extractor.Extract(request)

	if !errors.Is(err, credential.ErrMalformedCredential) {
		t.Fatalf(
			"expected ErrMalformedCredential, got %v",
			err,
		)
	}
}
