package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"simple-jwt-authenticator/internal/metrics"
)

const benchmarkRequestID = "benchmark-request-id"

type benchmarkResponseWriter struct {
	header http.Header
	status int
	bytes  int
}

func newBenchmarkResponseWriter() *benchmarkResponseWriter {
	return &benchmarkResponseWriter{
		header: make(http.Header),
	}
}

func (w *benchmarkResponseWriter) Header() http.Header {
	return w.header
}

func (w *benchmarkResponseWriter) WriteHeader(
	statusCode int,
) {
	if w.status != 0 {
		return
	}

	w.status = statusCode
}

func (w *benchmarkResponseWriter) Write(
	data []byte,
) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	w.bytes += len(data)

	return len(data), nil
}

func (w *benchmarkResponseWriter) reset() {
	clear(w.header)

	w.status = 0
	w.bytes = 0
}

func BenchmarkRequestID_Inbound(b *testing.B) {
	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if RequestIDFromContext(
				request.Context(),
			) == "" {
				b.Fatal(
					"request id is missing",
				)
			}

			writer.WriteHeader(
				http.StatusNoContent,
			)
		},
	)

	handler := RequestID(
		next,
	)

	request, err := http.NewRequest(
		http.MethodGet,
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
		RequestIDHeader,
		benchmarkRequestID,
	)

	writer := newBenchmarkResponseWriter()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		writer.reset()

		handler.ServeHTTP(
			writer,
			request,
		)
	}
}

func BenchmarkRequestID_Generated(b *testing.B) {
	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if RequestIDFromContext(
				request.Context(),
			) == "" {
				b.Fatal(
					"request id is missing",
				)
			}

			writer.WriteHeader(
				http.StatusNoContent,
			)
		},
	)

	handler := RequestID(
		next,
	)

	request, err := http.NewRequest(
		http.MethodGet,
		"http://example.test/healthz",
		nil,
	)
	if err != nil {
		b.Fatalf(
			"create request: %v",
			err,
		)
	}

	writer := newBenchmarkResponseWriter()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		writer.reset()

		handler.ServeHTTP(
			writer,
			request,
		)
	}
}

func BenchmarkRecovery_NoPanic(b *testing.B) {
	logger := slog.New(
		slog.NewJSONHandler(
			io.Discard,
			nil,
		),
	)

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

	handler := Recovery(
		logger,
		next,
	)

	request, err := http.NewRequest(
		http.MethodGet,
		"http://example.test/healthz",
		nil,
	)
	if err != nil {
		b.Fatalf(
			"create request: %v",
			err,
		)
	}

	writer := newBenchmarkResponseWriter()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		writer.reset()

		handler.ServeHTTP(
			writer,
			request,
		)
	}
}

func BenchmarkMetrics_Noop(b *testing.B) {
	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/healthz"

			writer.WriteHeader(
				http.StatusNoContent,
			)
		},
	)

	handler := Metrics(
		metrics.NoopRequestRecorder{},
		next,
	)

	request, err := http.NewRequest(
		http.MethodGet,
		"http://example.test/healthz",
		nil,
	)
	if err != nil {
		b.Fatalf(
			"create request: %v",
			err,
		)
	}

	writer := newBenchmarkResponseWriter()

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

func BenchmarkLogging_DisabledInfo(b *testing.B) {
	logger := slog.New(
		slog.NewJSONHandler(
			io.Discard,
			&slog.HandlerOptions{
				Level: slog.LevelError,
			},
		),
	)

	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/healthz"

			writer.WriteHeader(
				http.StatusNoContent,
			)
		},
	)

	handler := Logging(
		logger,
		next,
	)

	handler = RequestID(
		handler,
	)

	request, err := http.NewRequest(
		http.MethodGet,
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
		RequestIDHeader,
		benchmarkRequestID,
	)

	writer := newBenchmarkResponseWriter()

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

func BenchmarkLogging_JSONDiscard(b *testing.B) {
	logger := slog.New(
		slog.NewJSONHandler(
			io.Discard,
			nil,
		),
	)

	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/healthz"

			writer.WriteHeader(
				http.StatusNoContent,
			)
		},
	)

	handler := Logging(
		logger,
		next,
	)

	handler = RequestID(
		handler,
	)

	request, err := http.NewRequest(
		http.MethodGet,
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
		RequestIDHeader,
		benchmarkRequestID,
	)

	writer := newBenchmarkResponseWriter()

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

func BenchmarkMiddlewareChain_InboundRequestID(
	b *testing.B,
) {
	logger := slog.New(
		slog.NewJSONHandler(
			io.Discard,
			nil,
		),
	)

	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/healthz"

			writer.WriteHeader(
				http.StatusOK,
			)

			_, _ = writer.Write(
				[]byte("ok\n"),
			)
		},
	)

	handler := Recovery(
		logger,
		next,
	)

	handler = Metrics(
		metrics.NoopRequestRecorder{},
		handler,
	)

	handler = Logging(
		logger,
		handler,
	)

	handler = RequestID(
		handler,
	)

	request, err := http.NewRequest(
		http.MethodGet,
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
		RequestIDHeader,
		benchmarkRequestID,
	)

	writer := newBenchmarkResponseWriter()

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

func BenchmarkMiddlewareChain_GeneratedRequestID(
	b *testing.B,
) {
	logger := slog.New(
		slog.NewJSONHandler(
			io.Discard,
			nil,
		),
	)

	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/healthz"

			writer.WriteHeader(
				http.StatusOK,
			)

			_, _ = writer.Write(
				[]byte("ok\n"),
			)
		},
	)

	handler := Recovery(
		logger,
		next,
	)

	handler = Metrics(
		metrics.NoopRequestRecorder{},
		handler,
	)

	handler = Logging(
		logger,
		handler,
	)

	handler = RequestID(
		handler,
	)

	request, err := http.NewRequest(
		http.MethodGet,
		"http://example.test/healthz",
		nil,
	)
	if err != nil {
		b.Fatalf(
			"create request: %v",
			err,
		)
	}

	writer := newBenchmarkResponseWriter()

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
