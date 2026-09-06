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

func TestRecovery_ConvertsPanicTo500(
	t *testing.T,
) {
	logger := slog.New(
		slog.NewTextHandler(
			&bytes.Buffer{},
			nil,
		),
	)

	next := http.HandlerFunc(
		func(
			_ http.ResponseWriter,
			_ *http.Request,
		) {
			panic(
				"boom",
			)
		},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	recorder := httptest.NewRecorder()

	Recovery(
		logger,
		next,
	).ServeHTTP(
		recorder,
		request,
	)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusInternalServerError,
		)
	}

	if recorder.Body.String() != "internal server error" {
		t.Fatalf(
			"unexpected body: got %q, want %q",
			recorder.Body.String(),
			"internal server error",
		)
	}
}

func TestRecovery_LogsBoundedRequestContext(
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
		bytes.TrimSpace(
			buffer.Bytes(),
		),
		&entry,
	); err != nil {
		t.Fatalf(
			"decode recovery log: %v",
			err,
		)
	}

	if got := entry["msg"]; got != "recovered from panic" {
		t.Fatalf(
			"unexpected message: got %v",
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

	if _, exists := entry["path"]; exists {
		t.Fatal(
			"recovery log must not contain raw request path",
		)
	}
}

func TestRecovery_DoesNotLogRawUnmatchedPath(
	t *testing.T,
) {
	var buffer bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&buffer,
			nil,
		),
	)

	const sensitivePath = "/attacker/SECRET-VALUE"

	next := http.HandlerFunc(
		func(
			_ http.ResponseWriter,
			_ *http.Request,
		) {
			panic(
				"boom",
			)
		},
	)

	Recovery(
		logger,
		next,
	).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodGet,
			sensitivePath,
			nil,
		),
	)

	logged := buffer.String()

	if strings.Contains(
		logged,
		sensitivePath,
	) {
		t.Fatalf(
			"raw request path leaked to recovery log: %q",
			logged,
		)
	}

	var entry map[string]any

	if err := json.Unmarshal(
		bytes.TrimSpace(
			buffer.Bytes(),
		),
		&entry,
	); err != nil {
		t.Fatalf(
			"decode recovery log: %v",
			err,
		)
	}

	if got := entry["route"]; got != "unknown" {
		t.Fatalf(
			"unexpected unmatched route: got %v, want %q",
			got,
			"unknown",
		)
	}
}

func TestRecovery_DoesNotLogPanicValue(
	t *testing.T,
) {
	var buffer bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&buffer,
			&slog.HandlerOptions{
				Level: slog.LevelInfo,
			},
		),
	)

	const secret = "PANIC-SECRET-MUST-NOT-BE-LOGGED"

	next := http.HandlerFunc(
		func(
			_ http.ResponseWriter,
			_ *http.Request,
		) {
			panic(
				secret,
			)
		},
	)

	Recovery(
		logger,
		next,
	).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodGet,
			"/",
			nil,
		),
	)

	if strings.Contains(
		buffer.String(),
		secret,
	) {
		t.Fatalf(
			"panic value leaked to recovery log: %q",
			buffer.String(),
		)
	}
}
