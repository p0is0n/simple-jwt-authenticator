package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	next := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			id := RequestIDFromContext(r.Context())
			if id == "" {
				t.Fatal("expected generated request id in context")
			}

			w.WriteHeader(http.StatusOK)
		},
	)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()

	RequestID(next).ServeHTTP(recorder, request)

	if recorder.Header().Get(RequestIDHeader) == "" {
		t.Fatal("expected request id header on response")
	}
}

func TestRequestID_TrustsSafeInbound(t *testing.T) {
	next := http.HandlerFunc(
		func(_ http.ResponseWriter, r *http.Request) {
			id := RequestIDFromContext(r.Context())
			if id != "abc-123" {
				t.Fatalf(
					"expected trusted inbound id, got %q",
					id,
				)
			}
		},
	)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(RequestIDHeader, "abc-123")

	RequestID(next).ServeHTTP(httptest.NewRecorder(), request)
}

func TestRequestID_RejectsUnsafeInbound(t *testing.T) {
	next := http.HandlerFunc(
		func(_ http.ResponseWriter, r *http.Request) {
			id := RequestIDFromContext(r.Context())
			if id == "" {
				t.Fatal("expected generated request id")
			}

			if id == "evil\r\n" {
				t.Fatal("unsafe inbound id must not be trusted")
			}
		},
	)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(RequestIDHeader, "evil\r\n")

	RequestID(next).ServeHTTP(httptest.NewRecorder(), request)
}
