package extractor

import (
	"net/http"
	"testing"

	"simple-jwt-authenticator/internal/transport/http/credential"
)

var (
	benchmarkExtractionResult credential.Result
	benchmarkExtractionError  error
)

func BenchmarkAuthorizationHeader_ExtractValidBearer(
	b *testing.B,
) {
	request := &http.Request{
		Header: make(http.Header),
	}

	request.Header.Set(
		"Authorization",
		"Bearer eyJhbGciOiJSUzI1NiJ9.benchmark.signature",
	)

	extractor := AuthorizationHeader{}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkExtractionResult,
			benchmarkExtractionError = extractor.Extract(
			request,
		)
	}

	if benchmarkExtractionError != nil {
		b.Fatalf(
			"Extract() error = %v, want nil",
			benchmarkExtractionError,
		)
	}

	if !benchmarkExtractionResult.Extracted {
		b.Fatal(
			"credential was not extracted",
		)
	}
}

func BenchmarkAuthorizationHeader_Absent(
	b *testing.B,
) {
	request := &http.Request{
		Header: make(http.Header),
	}

	extractor := AuthorizationHeader{}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkExtractionResult,
			benchmarkExtractionError = extractor.Extract(
			request,
		)
	}

	if benchmarkExtractionError != nil {
		b.Fatalf(
			"Extract() error = %v, want nil",
			benchmarkExtractionError,
		)
	}

	if !benchmarkExtractionResult.NotApplicable {
		b.Fatal(
			"extractor must be not applicable",
		)
	}
}

func BenchmarkAuthorizationHeader_MalformedBearer(
	b *testing.B,
) {
	request := &http.Request{
		Header: make(http.Header),
	}

	request.Header.Set(
		"Authorization",
		"Bearer",
	)

	extractor := AuthorizationHeader{}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkExtractionResult,
			benchmarkExtractionError = extractor.Extract(
			request,
		)
	}

	if benchmarkExtractionError == nil {
		b.Fatal(
			"Extract() error = nil, want malformed credential error",
		)
	}
}

func BenchmarkCookie_ExtractValid(
	b *testing.B,
) {
	extractor, err := NewCookie(
		"auth_token",
	)
	if err != nil {
		b.Fatalf(
			"NewCookie() error = %v, want nil",
			err,
		)
	}

	request := &http.Request{
		Header: make(http.Header),
	}

	request.Header.Set(
		"Cookie",
		"other=value; auth_token=eyJhbGciOiJSUzI1NiJ9.benchmark.signature",
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkExtractionResult,
			benchmarkExtractionError = extractor.Extract(
			request,
		)
	}

	if benchmarkExtractionError != nil {
		b.Fatalf(
			"Extract() error = %v, want nil",
			benchmarkExtractionError,
		)
	}

	if !benchmarkExtractionResult.Extracted {
		b.Fatal(
			"credential was not extracted",
		)
	}
}

func BenchmarkCookie_Absent(
	b *testing.B,
) {
	extractor, err := NewCookie(
		"auth_token",
	)
	if err != nil {
		b.Fatalf(
			"NewCookie() error = %v, want nil",
			err,
		)
	}

	request := &http.Request{
		Header: make(http.Header),
	}

	request.Header.Set(
		"Cookie",
		"session=benchmark; another=value",
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkExtractionResult,
			benchmarkExtractionError = extractor.Extract(
			request,
		)
	}

	if benchmarkExtractionError != nil {
		b.Fatalf(
			"Extract() error = %v, want nil",
			benchmarkExtractionError,
		)
	}

	if !benchmarkExtractionResult.NotApplicable {
		b.Fatal(
			"extractor must be not applicable",
		)
	}
}

func BenchmarkCookie_DuplicateFailsClosed(
	b *testing.B,
) {
	extractor, err := NewCookie(
		"auth_token",
	)
	if err != nil {
		b.Fatalf(
			"NewCookie() error = %v, want nil",
			err,
		)
	}

	request := &http.Request{
		Header: make(http.Header),
	}

	request.Header.Add(
		"Cookie",
		"auth_token=first",
	)

	request.Header.Add(
		"Cookie",
		"auth_token=second",
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		benchmarkExtractionResult,
			benchmarkExtractionError = extractor.Extract(
			request,
		)
	}

	if benchmarkExtractionError == nil {
		b.Fatal(
			"Extract() error = nil, want duplicate credential error",
		)
	}
}
