package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"simple-jwt-authenticator/internal/metrics"
)

func TestMiddlewareChain_ProvidesRequestIDAndRecordsMetrics(
	t *testing.T,
) {
	logger := slog.New(
		slog.NewTextHandler(
			io.Discard,
			nil,
		),
	)

	recorder := &recordingRequestRecorder{}

	inner := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if RequestIDFromContext(
				request.Context(),
			) == "" {
				t.Fatal(
					"expected request id available to inner handler",
				)
			}

			request.Pattern = "/healthz"

			writer.WriteHeader(
				http.StatusOK,
			)
		},
	)

	handler := chainHandlerForTest(
		logger,
		recorder,
		inner,
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/healthz",
		nil,
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(
		response,
		request,
	)

	if response.Header().Get(
		RequestIDHeader,
	) == "" {
		t.Fatal(
			"expected request id header on response",
		)
	}

	if recorder.calls != 1 {
		t.Fatalf(
			"unexpected recorder call count: got %d, want 1",
			recorder.calls,
		)
	}

	if recorder.result != metrics.ResultSuccess {
		t.Fatalf(
			"unexpected metric result: got %q, want %q",
			recorder.result,
			metrics.ResultSuccess,
		)
	}
}

func TestMiddlewareChain_RecordsRecoveredPanicAsFailure(
	t *testing.T,
) {
	logger := slog.New(
		slog.NewTextHandler(
			io.Discard,
			nil,
		),
	)

	recorder := &recordingRequestRecorder{}

	inner := http.HandlerFunc(
		func(
			_ http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/auth/nginx"

			panic(
				"boom",
			)
		},
	)

	handler := chainHandlerForTest(
		logger,
		recorder,
		inner,
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(
		response,
		request,
	)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"unexpected response status: got %d, want %d",
			response.Code,
			http.StatusInternalServerError,
		)
	}

	if recorder.calls != 1 {
		t.Fatalf(
			"unexpected recorder call count: got %d, want 1",
			recorder.calls,
		)
	}

	if recorder.result != metrics.ResultFailure {
		t.Fatalf(
			"unexpected metric result: got %q, want %q",
			recorder.result,
			metrics.ResultFailure,
		)
	}
}

func TestMiddlewareChain_AccessLogObservesRecovered500(
	t *testing.T,
) {
	var logs bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&logs,
			nil,
		),
	)

	recorder := &recordingRequestRecorder{}

	inner := http.HandlerFunc(
		func(
			_ http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/auth/nginx"

			panic(
				"boom",
			)
		},
	)

	handler := chainHandlerForTest(
		logger,
		recorder,
		inner,
	)

	handler.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodGet,
			"/auth/nginx",
			nil,
		),
	)

	entries := decodeChainLogEntries(
		t,
		logs.String(),
	)

	var accessLog map[string]any

	for _, entry := range entries {
		if entry["msg"] == "http request" {
			accessLog = entry

			break
		}
	}

	if accessLog == nil {
		t.Fatalf(
			"access log entry not found: %s",
			logs.String(),
		)
	}

	if got := accessLog["status"]; got != float64(
		http.StatusInternalServerError,
	) {
		t.Fatalf(
			"unexpected access log status: got %v, want %d",
			got,
			http.StatusInternalServerError,
		)
	}

	if got := accessLog["route"]; got != "/auth/nginx" {
		t.Fatalf(
			"unexpected access log route: got %v, want %q",
			got,
			"/auth/nginx",
		)
	}

	if got := accessLog["method"]; got != http.MethodGet {
		t.Fatalf(
			"unexpected access log method: got %v, want %q",
			got,
			http.MethodGet,
		)
	}

	requestID, ok := accessLog["request_id"].(string)
	if !ok || requestID == "" {
		t.Fatalf(
			"access log request_id is missing or invalid: %v",
			accessLog["request_id"],
		)
	}

	var recoveryLog map[string]any

	for _, entry := range entries {
		if entry["msg"] == "recovered from panic" {
			recoveryLog = entry

			break
		}
	}

	if recoveryLog == nil {
		t.Fatalf(
			"recovery log entry not found: %s",
			logs.String(),
		)
	}

	if got := recoveryLog["request_id"]; got != requestID {
		t.Fatalf(
			"request id mismatch between recovery and access logs: recovery=%v access=%q",
			got,
			requestID,
		)
	}

	if got := recoveryLog["route"]; got != "/auth/nginx" {
		t.Fatalf(
			"unexpected recovery route: got %v, want %q",
			got,
			"/auth/nginx",
		)
	}

	if _, exists := recoveryLog["path"]; exists {
		t.Fatal(
			"recovery log must not contain raw request path",
		)
	}
}

// chainHandlerForTest mirrors the production HTTP middleware ordering:
//
//	RequestID
//	Logging
//	Metrics
//	Recovery
//	Router
//
// Keep this helper synchronized with internal/transport/http.NewHandler.
func chainHandlerForTest(
	logger *slog.Logger,
	recorder metrics.RequestRecorder,
	router http.Handler,
) http.Handler {
	handler := Recovery(
		logger,
		router,
	)

	handler = Metrics(
		recorder,
		handler,
	)

	handler = Logging(
		logger,
		handler,
	)

	handler = RequestID(
		handler,
	)

	return handler
}

func decodeChainLogEntries(
	t testing.TB,
	logged string,
) []map[string]any {
	t.Helper()

	lines := strings.Split(
		strings.TrimSpace(logged),
		"\n",
	)

	entries := make(
		[]map[string]any,
		0,
		len(lines),
	)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var entry map[string]any

		if err := json.Unmarshal(
			[]byte(line),
			&entry,
		); err != nil {
			t.Fatalf(
				"decode JSON log entry %q: %v",
				line,
				err,
			)
		}

		entries = append(
			entries,
			entry,
		)
	}

	return entries
}
