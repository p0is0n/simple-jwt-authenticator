package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"simple-jwt-authenticator/internal/metrics"
)

// recordingRequestRecorder captures the latest request metric observation.
type recordingRequestRecorder struct {
	handler   string
	operation string
	result    metrics.Result
	duration  time.Duration
	calls     int
}

func (r *recordingRequestRecorder) RecordRequest(
	_ context.Context,
	handler string,
	operation string,
	result metrics.Result,
	duration time.Duration,
) {
	r.handler = handler
	r.operation = operation
	r.result = result
	r.duration = duration
	r.calls++
}

func TestMetrics_RecordsRequest(
	t *testing.T,
) {
	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(
				http.StatusNoContent,
			)
		},
	)

	recorder := &recordingRequestRecorder{}

	request := httptest.NewRequest(
		http.MethodGet,
		"/healthz",
		nil,
	)

	request.Pattern = "/healthz"

	Metrics(
		recorder,
		next,
	).ServeHTTP(
		httptest.NewRecorder(),
		request,
	)

	if recorder.calls != 1 {
		t.Fatalf(
			"unexpected recorder call count: got %d, want 1",
			recorder.calls,
		)
	}

	if recorder.handler != "/healthz" {
		t.Fatalf(
			"unexpected handler: got %q, want %q",
			recorder.handler,
			"/healthz",
		)
	}

	if recorder.operation != http.MethodGet {
		t.Fatalf(
			"unexpected operation: got %q, want %q",
			recorder.operation,
			http.MethodGet,
		)
	}

	if recorder.result != metrics.ResultSuccess {
		t.Fatalf(
			"unexpected result: got %q, want %q",
			recorder.result,
			metrics.ResultSuccess,
		)
	}

	if recorder.duration < 0 {
		t.Fatalf(
			"unexpected negative duration: %s",
			recorder.duration,
		)
	}
}

func TestMetrics_UsesUnknownForUnmatchedRoute(
	t *testing.T,
) {
	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(
				http.StatusNotFound,
			)
		},
	)

	recorder := &recordingRequestRecorder{}

	request := httptest.NewRequest(
		http.MethodGet,
		"/attacker-controlled-path",
		nil,
	)

	Metrics(
		recorder,
		next,
	).ServeHTTP(
		httptest.NewRecorder(),
		request,
	)

	if recorder.handler != "unknown" {
		t.Fatalf(
			"unexpected unmatched handler identity: got %q, want %q",
			recorder.handler,
			"unknown",
		)
	}
}

func TestMetrics_RecordsExactlyOnce(
	t *testing.T,
) {
	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(
				http.StatusOK,
			)
		},
	)

	recorder := &recordingRequestRecorder{}

	request := httptest.NewRequest(
		http.MethodGet,
		"/healthz",
		nil,
	)

	Metrics(
		recorder,
		next,
	).ServeHTTP(
		httptest.NewRecorder(),
		request,
	)

	if recorder.calls != 1 {
		t.Fatalf(
			"unexpected recorder call count: got %d, want 1",
			recorder.calls,
		)
	}
}

func TestRequestResult(
	t *testing.T,
) {
	tests := []struct {
		name       string
		statusCode int
		want       metrics.Result
	}{
		{
			name:       "informational",
			statusCode: http.StatusContinue,
			want:       metrics.ResultSuccess,
		},
		{
			name:       "success",
			statusCode: http.StatusOK,
			want:       metrics.ResultSuccess,
		},
		{
			name:       "no content",
			statusCode: http.StatusNoContent,
			want:       metrics.ResultSuccess,
		},
		{
			name:       "redirection",
			statusCode: http.StatusFound,
			want:       metrics.ResultSuccess,
		},
		{
			name:       "bad request",
			statusCode: http.StatusBadRequest,
			want:       metrics.ResultFailure,
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       metrics.ResultFailure,
		},
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
			want:       metrics.ResultFailure,
		},
		{
			name:       "server error",
			statusCode: http.StatusInternalServerError,
			want:       metrics.ResultFailure,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				got := requestResult(
					tt.statusCode,
				)

				if got != tt.want {
					t.Fatalf(
						"requestResult(%d): got %q, want %q",
						tt.statusCode,
						got,
						tt.want,
					)
				}
			},
		)
	}
}

func TestHandlerIdentityUsesMatchedPattern(
	t *testing.T,
) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	request.Pattern = "/auth/nginx"

	if got := handlerIdentity(request); got != "/auth/nginx" {
		t.Fatalf(
			"unexpected handler identity: got %q, want %q",
			got,
			"/auth/nginx",
		)
	}
}

func TestHandlerIdentityDoesNotUseRawUnmatchedPath(
	t *testing.T,
) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/secret/token/value",
		nil,
	)

	if got := handlerIdentity(request); got != "unknown" {
		t.Fatalf(
			"unexpected handler identity: got %q, want %q",
			got,
			"unknown",
		)
	}
}
