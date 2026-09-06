package credential

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token"
)

type stubExtractor struct {
	result Result
	err    error
	calls  int
}

func (s *stubExtractor) Extract(_ *http.Request) (Result, error) {
	s.calls++

	return s.result, s.err
}

func extracted(source Source, value string) Result {
	return Result{
		Credential: authentication.Credential{
			Value: token.Value(value),
		},
		Source:    source,
		Extracted: true,
	}
}

func notApplicable(source Source) Result {
	return Result{
		Source:        source,
		NotApplicable: true,
	}
}

func malformed(source Source) Result {
	return Result{
		Source: source,
	}
}

func TestProvider_FirstExtractedCredentialWins(t *testing.T) {
	first := &stubExtractor{
		result: extracted(
			SourceAuthorizationHeader,
			"from-header",
		),
	}

	second := &stubExtractor{
		result: extracted(
			SourceCookie,
			"from-cookie",
		),
	}

	provider, err := NewProvider(first, second)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := provider.Extract(
		httptest.NewRequest(http.MethodGet, "/", nil),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Credential.Value != "from-header" {
		t.Fatalf(
			"unexpected credential value: got %q, want %q",
			result.Credential.Value,
			"from-header",
		)
	}

	if first.calls != 1 {
		t.Fatalf(
			"unexpected first extractor calls: got %d, want 1",
			first.calls,
		)
	}

	if second.calls != 0 {
		t.Fatalf(
			"lower-priority extractor must not be called after extraction: got %d calls",
			second.calls,
		)
	}
}

func TestProvider_NotApplicableFallsBackToNextExtractor(t *testing.T) {
	first := &stubExtractor{
		result: notApplicable(SourceAuthorizationHeader),
	}

	second := &stubExtractor{
		result: extracted(
			SourceCookie,
			"from-cookie",
		),
	}

	provider, err := NewProvider(first, second)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := provider.Extract(
		httptest.NewRequest(http.MethodGet, "/", nil),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Credential.Value != "from-cookie" {
		t.Fatalf(
			"unexpected credential value: got %q, want %q",
			result.Credential.Value,
			"from-cookie",
		)
	}

	if first.calls != 1 {
		t.Fatalf(
			"unexpected first extractor calls: got %d, want 1",
			first.calls,
		)
	}

	if second.calls != 1 {
		t.Fatalf(
			"unexpected second extractor calls: got %d, want 1",
			second.calls,
		)
	}
}

func TestProvider_TerminalErrorStopsExtraction(t *testing.T) {
	first := &stubExtractor{
		result: malformed(SourceAuthorizationHeader),
		err:    ErrMalformedCredential,
	}

	second := &stubExtractor{
		result: extracted(
			SourceCookie,
			"from-cookie",
		),
	}

	provider, err := NewProvider(first, second)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := provider.Extract(
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	if !errors.Is(err, ErrMalformedCredential) {
		t.Fatalf(
			"expected ErrMalformedCredential, got %v",
			err,
		)
	}

	if result.Source != SourceAuthorizationHeader {
		t.Fatalf(
			"unexpected source: got %q, want %q",
			result.Source,
			SourceAuthorizationHeader,
		)
	}

	if second.calls != 0 {
		t.Fatalf(
			"lower-priority extractor must not be called after terminal error: got %d calls",
			second.calls,
		)
	}
}

func TestProvider_NoExtractorsRejected(t *testing.T) {
	_, err := NewProvider()

	if !errors.Is(err, ErrNoExtractors) {
		t.Fatalf(
			"expected ErrNoExtractors, got %v",
			err,
		)
	}

	if errors.Is(err, ErrMissingCredential) {
		t.Fatal(
			"provider construction error must not be classified as missing credential",
		)
	}
}

func TestProvider_NoCredentialReturnsMissingCredential(t *testing.T) {
	first := &stubExtractor{
		result: notApplicable(SourceAuthorizationHeader),
	}

	second := &stubExtractor{
		result: notApplicable(SourceCookie),
	}

	provider, err := NewProvider(first, second)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := provider.Extract(
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	if !errors.Is(err, ErrMissingCredential) {
		t.Fatalf(
			"expected ErrMissingCredential, got %v",
			err,
		)
	}

	if result.Extracted {
		t.Fatal("expected credential not to be extracted")
	}

	if !result.NotApplicable {
		t.Fatal("expected final result to be not applicable")
	}

	if result.Source != SourceCookie {
		t.Fatalf(
			"unexpected final source: got %q, want %q",
			result.Source,
			SourceCookie,
		)
	}

	if first.calls != 1 {
		t.Fatalf(
			"unexpected first extractor calls: got %d, want 1",
			first.calls,
		)
	}

	if second.calls != 1 {
		t.Fatalf(
			"unexpected second extractor calls: got %d, want 1",
			second.calls,
		)
	}
}
