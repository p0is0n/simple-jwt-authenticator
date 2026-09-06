package credential_test

import (
	"net/http"
	"testing"

	"simple-jwt-authenticator/internal/transport/http/credential"
	"simple-jwt-authenticator/internal/transport/http/credential/extractor"
)

var (
	benchmarkProviderResult credential.Result
	benchmarkProviderError  error
)

func BenchmarkProvider_AuthorizationWins(
	b *testing.B,
) {
	cookie, err := extractor.NewCookie(
		"auth_token",
	)
	if err != nil {
		b.Fatalf(
			"NewCookie() error = %v, want nil",
			err,
		)
	}

	provider, err := credential.NewProvider(
		extractor.AuthorizationHeader{},
		cookie,
	)
	if err != nil {
		b.Fatalf(
			"NewProvider() error = %v, want nil",
			err,
		)
	}

	request := &http.Request{
		Header: make(http.Header),
	}

	request.Header.Set(
		"Authorization",
		"Bearer header-token",
	)

	request.Header.Set(
		"Cookie",
		"auth_token=cookie-token",
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkProviderResult,
			benchmarkProviderError = provider.Extract(
			request,
		)
	}

	if benchmarkProviderError != nil {
		b.Fatalf(
			"Extract() error = %v, want nil",
			benchmarkProviderError,
		)
	}

	if benchmarkProviderResult.Source !=
		credential.SourceAuthorizationHeader {
		b.Fatalf(
			"source = %q, want %q",
			benchmarkProviderResult.Source,
			credential.SourceAuthorizationHeader,
		)
	}
}

func BenchmarkProvider_FallbackToCookie(
	b *testing.B,
) {
	cookie, err := extractor.NewCookie(
		"auth_token",
	)
	if err != nil {
		b.Fatalf(
			"NewCookie() error = %v, want nil",
			err,
		)
	}

	provider, err := credential.NewProvider(
		extractor.AuthorizationHeader{},
		cookie,
	)
	if err != nil {
		b.Fatalf(
			"NewProvider() error = %v, want nil",
			err,
		)
	}

	request := &http.Request{
		Header: make(http.Header),
	}

	request.Header.Set(
		"Cookie",
		"auth_token=cookie-token",
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkProviderResult,
			benchmarkProviderError = provider.Extract(
			request,
		)
	}

	if benchmarkProviderError != nil {
		b.Fatalf(
			"Extract() error = %v, want nil",
			benchmarkProviderError,
		)
	}

	if benchmarkProviderResult.Source !=
		credential.SourceCookie {
		b.Fatalf(
			"source = %q, want %q",
			benchmarkProviderResult.Source,
			credential.SourceCookie,
		)
	}
}

func BenchmarkProvider_NoCredential(
	b *testing.B,
) {
	cookie, err := extractor.NewCookie(
		"auth_token",
	)
	if err != nil {
		b.Fatalf(
			"NewCookie() error = %v, want nil",
			err,
		)
	}

	provider, err := credential.NewProvider(
		extractor.AuthorizationHeader{},
		cookie,
	)
	if err != nil {
		b.Fatalf(
			"NewProvider() error = %v, want nil",
			err,
		)
	}

	request := &http.Request{
		Header: make(http.Header),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkProviderResult,
			benchmarkProviderError = provider.Extract(
			request,
		)
	}

	if benchmarkProviderError == nil {
		b.Fatal(
			"Extract() error = nil, want missing credential error",
		)
	}
}

func BenchmarkProvider_MalformedAuthorizationStopsFallback(
	b *testing.B,
) {
	cookie, err := extractor.NewCookie(
		"auth_token",
	)
	if err != nil {
		b.Fatalf(
			"NewCookie() error = %v, want nil",
			err,
		)
	}

	provider, err := credential.NewProvider(
		extractor.AuthorizationHeader{},
		cookie,
	)
	if err != nil {
		b.Fatalf(
			"NewProvider() error = %v, want nil",
			err,
		)
	}

	request := &http.Request{
		Header: make(http.Header),
	}

	request.Header.Set(
		"Authorization",
		"Bearer",
	)

	request.Header.Set(
		"Cookie",
		"auth_token=valid-cookie-token",
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkProviderResult,
			benchmarkProviderError = provider.Extract(
			request,
		)
	}

	if benchmarkProviderError == nil {
		b.Fatal(
			"Extract() error = nil, want malformed Authorization error",
		)
	}
}
