package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogging_WritesCompletedRequestEvent(
	t *testing.T,
) {
	var buffer bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&buffer,
			nil,
		),
	)

	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/auth/nginx"

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

	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	request.Header.Set(
		RequestIDHeader,
		"request-test-123",
	)

	handler.ServeHTTP(
		httptest.NewRecorder(),
		request,
	)

	var entry map[string]any

	if err := json.Unmarshal(
		bytes.TrimSpace(buffer.Bytes()),
		&entry,
	); err != nil {
		t.Fatalf(
			"decode log entry: %v",
			err,
		)
	}

	if got := entry["msg"]; got != "http request" {
		t.Fatalf(
			"unexpected log message: got %v",
			got,
		)
	}

	if got := entry["request_id"]; got != "request-test-123" {
		t.Fatalf(
			"unexpected request id: got %v",
			got,
		)
	}

	if got := entry["route"]; got != "/auth/nginx" {
		t.Fatalf(
			"unexpected route: got %v",
			got,
		)
	}

	if got := entry["method"]; got != http.MethodGet {
		t.Fatalf(
			"unexpected method: got %v",
			got,
		)
	}

	if got := entry["status"]; got != float64(
		http.StatusNoContent,
	) {
		t.Fatalf(
			"unexpected status: got %v",
			got,
		)
	}

	if _, ok := entry["duration"]; !ok {
		t.Fatal(
			"expected duration field",
		)
	}
}

func TestLogging_UsesFinalRecoveredStatus(
	t *testing.T,
) {
	var buffer bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&buffer,
			nil,
		),
	)

	next := http.HandlerFunc(
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

	handler := Recovery(
		logger,
		next,
	)

	handler = Logging(
		logger,
		handler,
	)

	handler = RequestID(
		handler,
	)

	handler.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodGet,
			"/auth/nginx",
			nil,
		),
	)

	entries := decodeJSONLogEntries(
		t,
		buffer.String(),
	)

	var accessLog map[string]any

	for _, entry := range entries {
		if entry["msg"] == "http request" {
			accessLog = entry

			break
		}
	}

	if accessLog == nil {
		t.Fatal(
			"access log entry not found",
		)
	}

	if got := accessLog["status"]; got != float64(
		http.StatusInternalServerError,
	) {
		t.Fatalf(
			"unexpected recovered status: got %v, want %d",
			got,
			http.StatusInternalServerError,
		)
	}
}

func TestLogging_DoesNotLogSensitiveRequestData(
	t *testing.T,
) {
	var buffer bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&buffer,
			nil,
		),
	)

	const (
		tokenMarker      = "JWT-MUST-NOT-APPEAR-IN-LOG"
		cookieMarker     = "COOKIE-MUST-NOT-APPEAR-IN-LOG"
		expressionMarker = "POLICY-MUST-NOT-APPEAR-IN-LOG"
		queryMarker      = "QUERY-SECRET-MUST-NOT-APPEAR-IN-LOG"
		subjectMarker    = "SUBJECT-MUST-NOT-APPEAR-IN-LOG"
	)

	next := http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			request.Pattern = "/auth/nginx"

			writer.Header().Set(
				"X-Auth-Subject",
				subjectMarker,
			)

			writer.WriteHeader(
				http.StatusUnauthorized,
			)
		},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx?access_token="+queryMarker+
			"&claim-expression="+expressionMarker,
		nil,
	)

	request.Header.Set(
		"Authorization",
		"Bearer "+tokenMarker,
	)

	request.Header.Set(
		"Cookie",
		"auth_token="+cookieMarker,
	)

	request.Header.Set(
		"X-Auth-Claim-Expression",
		expressionMarker,
	)

	handler := Logging(
		logger,
		next,
	)

	handler = RequestID(
		handler,
	)

	handler.ServeHTTP(
		httptest.NewRecorder(),
		request,
	)

	logged := buffer.String()

	for _, forbidden := range []string{
		tokenMarker,
		cookieMarker,
		expressionMarker,
		queryMarker,
		subjectMarker,
		"Authorization",
		"Cookie",
		"access_token",
		"claim-expression",
	} {
		if strings.Contains(
			logged,
			forbidden,
		) {
			t.Fatalf(
				"sensitive request data leaked to access log: %q",
				forbidden,
			)
		}
	}
}

func TestLogging_UnmatchedRequestDoesNotLogRawPath(
	t *testing.T,
) {
	var buffer bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&buffer,
			nil,
		),
	)

	const secretPath = "/attacker/SECRET-PATH-VALUE"

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

	request := httptest.NewRequest(
		http.MethodGet,
		secretPath,
		nil,
	)

	handler := Logging(
		logger,
		next,
	)

	handler = RequestID(
		handler,
	)

	handler.ServeHTTP(
		httptest.NewRecorder(),
		request,
	)

	logged := buffer.String()

	if strings.Contains(
		logged,
		secretPath,
	) {
		t.Fatalf(
			"raw unmatched request path leaked to access log: %q",
			logged,
		)
	}

	var entry map[string]any

	if err := json.Unmarshal(
		bytes.TrimSpace(buffer.Bytes()),
		&entry,
	); err != nil {
		t.Fatalf(
			"decode log entry: %v",
			err,
		)
	}

	if got := entry["route"]; got != "unknown" {
		t.Fatalf(
			"unexpected unmatched route identity: got %v, want %q",
			got,
			"unknown",
		)
	}
}

func decodeJSONLogEntries(
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
