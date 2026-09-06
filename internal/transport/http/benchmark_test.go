package http

import (
	"io"
	"log/slog"
	stdhttp "net/http"
	"testing"

	"simple-jwt-authenticator/internal/metrics"
	"simple-jwt-authenticator/internal/transport/http/middleware"
)

type benchmarkHTTPWriter struct {
	header stdhttp.Header
	status int
	bytes  int
}

func newBenchmarkHTTPWriter() *benchmarkHTTPWriter {
	return &benchmarkHTTPWriter{
		header: make(stdhttp.Header),
	}
}

func (w *benchmarkHTTPWriter) Header() stdhttp.Header {
	return w.header
}

func (w *benchmarkHTTPWriter) WriteHeader(
	statusCode int,
) {
	if w.status != 0 {
		return
	}

	w.status = statusCode
}

func (w *benchmarkHTTPWriter) Write(
	data []byte,
) (int, error) {
	if w.status == 0 {
		w.status = stdhttp.StatusOK
	}

	w.bytes += len(data)

	return len(data), nil
}

func (w *benchmarkHTTPWriter) reset() {
	clear(w.header)

	w.status = 0
	w.bytes = 0
}

func BenchmarkHandler_HealthLikeRequest(
	b *testing.B,
) {
	logger := slog.New(
		slog.NewJSONHandler(
			io.Discard,
			nil,
		),
	)

	noop := metrics.NewNoop()

	router := stdhttp.HandlerFunc(
		func(
			writer stdhttp.ResponseWriter,
			request *stdhttp.Request,
		) {
			request.Pattern = "/healthz"

			writer.WriteHeader(
				stdhttp.StatusOK,
			)

			_, _ = writer.Write(
				[]byte("ok\n"),
			)
		},
	)

	handler := NewHandler(
		logger,
		noop.Requests,
		router,
	)

	request, err := stdhttp.NewRequest(
		stdhttp.MethodGet,
		"http://example.test/healthz",
		nil,
	)
	if err != nil {
		b.Fatalf(
			"create request: %v",
			err,
		)
	}

	request.Header.Set(
		middleware.RequestIDHeader,
		"benchmark-request-id",
	)

	writer := newBenchmarkHTTPWriter()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		writer.reset()
		request.Pattern = ""

		handler.ServeHTTP(
			writer,
			request,
		)
	}
}

func BenchmarkHandler_HealthLikeRequestGeneratedID(
	b *testing.B,
) {
	logger := slog.New(
		slog.NewJSONHandler(
			io.Discard,
			nil,
		),
	)

	noop := metrics.NewNoop()

	router := stdhttp.HandlerFunc(
		func(
			writer stdhttp.ResponseWriter,
			request *stdhttp.Request,
		) {
			request.Pattern = "/healthz"

			writer.WriteHeader(
				stdhttp.StatusOK,
			)

			_, _ = writer.Write(
				[]byte("ok\n"),
			)
		},
	)

	handler := NewHandler(
		logger,
		noop.Requests,
		router,
	)

	request, err := stdhttp.NewRequest(
		stdhttp.MethodGet,
		"http://example.test/healthz",
		nil,
	)
	if err != nil {
		b.Fatalf(
			"create request: %v",
			err,
		)
	}

	writer := newBenchmarkHTTPWriter()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		writer.reset()
		request.Pattern = ""

		handler.ServeHTTP(
			writer,
			request,
		)
	}
}
