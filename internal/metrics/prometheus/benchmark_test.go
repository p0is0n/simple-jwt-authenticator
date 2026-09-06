package prometheus

import (
	"context"
	"testing"
	"time"

	"simple-jwt-authenticator/internal/metrics"
)

func BenchmarkRecordRequest_ExistingLabels(
	b *testing.B,
) {
	recorder := New()

	ctx := context.Background()

	// Prime metric vectors before starting the benchmark. This benchmark is
	// intended to measure steady-state recording rather than first-seen label
	// initialization.
	recorder.RecordRequest(
		ctx,
		"/auth/nginx",
		"GET",
		metrics.ResultSuccess,
		100*time.Microsecond,
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		recorder.RecordRequest(
			ctx,
			"/auth/nginx",
			"GET",
			metrics.ResultSuccess,
			100*time.Microsecond,
		)
	}
}

func BenchmarkRecordAuth_SuccessExistingLabels(
	b *testing.B,
) {
	recorder := New()

	ctx := context.Background()

	recorder.RecordAuth(
		ctx,
		"http-auth-nginx",
		metrics.ResultSuccess,
		"authorization_header",
		"",
		30*time.Microsecond,
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		recorder.RecordAuth(
			ctx,
			"http-auth-nginx",
			metrics.ResultSuccess,
			"authorization_header",
			"",
			30*time.Microsecond,
		)
	}
}

func BenchmarkRecordAuth_FailureExistingLabels(
	b *testing.B,
) {
	recorder := New()

	ctx := context.Background()

	recorder.RecordAuth(
		ctx,
		"http-auth-nginx",
		metrics.ResultFailure,
		"authorization_header",
		metrics.ReasonInvalidSignature,
		30*time.Microsecond,
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		recorder.RecordAuth(
			ctx,
			"http-auth-nginx",
			metrics.ResultFailure,
			"authorization_header",
			metrics.ReasonInvalidSignature,
			30*time.Microsecond,
		)
	}
}

func BenchmarkRecordRequest_Parallel(
	b *testing.B,
) {
	recorder := New()

	ctx := context.Background()

	recorder.RecordRequest(
		ctx,
		"/auth/nginx",
		"GET",
		metrics.ResultSuccess,
		100*time.Microsecond,
	)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				recorder.RecordRequest(
					ctx,
					"/auth/nginx",
					"GET",
					metrics.ResultSuccess,
					100*time.Microsecond,
				)
			}
		},
	)
}

func BenchmarkRecordAuth_Parallel(
	b *testing.B,
) {
	recorder := New()

	ctx := context.Background()

	recorder.RecordAuth(
		ctx,
		"http-auth-nginx",
		metrics.ResultSuccess,
		"authorization_header",
		"",
		30*time.Microsecond,
	)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				recorder.RecordAuth(
					ctx,
					"http-auth-nginx",
					metrics.ResultSuccess,
					"authorization_header",
					"",
					30*time.Microsecond,
				)
			}
		},
	)
}

func BenchmarkRegistry_Gather(
	b *testing.B,
) {
	recorder := New()

	ctx := context.Background()

	for range 1000 {
		recorder.RecordRequest(
			ctx,
			"/auth/nginx",
			"GET",
			metrics.ResultSuccess,
			100*time.Microsecond,
		)

		recorder.RecordAuth(
			ctx,
			"http-auth-nginx",
			metrics.ResultSuccess,
			"authorization_header",
			"",
			30*time.Microsecond,
		)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		families, err := recorder.Registry().Gather()
		if err != nil {
			b.Fatalf(
				"Gather() error = %v, want nil",
				err,
			)
		}

		if len(families) == 0 {
			b.Fatal(
				"Gather() returned no metric families",
			)
		}
	}
}
