package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubHandler is a simple HTTP handler used as the metrics exposition
// handler stand-in.
type stubHandler struct {
	called bool
}

func (s *stubHandler) ServeHTTP(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	s.called = true

	writer.WriteHeader(http.StatusAccepted)

	_, _ = writer.Write([]byte("metrics\n"))
}

func TestHandler_GetDelegates(t *testing.T) {
	stub := &stubHandler{}
	handler := NewHandler("/metrics", stub)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if !stub.called {
		t.Fatal("expected delegate handler to be called")
	}

	if recorder.Code != http.StatusAccepted {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusAccepted,
		)
	}

	if recorder.Body.String() != "metrics\n" {
		t.Fatalf(
			"unexpected body: got %q, want %q",
			recorder.Body.String(),
			"metrics\n",
		)
	}
}

func TestHandler_PostNotAllowed(t *testing.T) {
	stub := &stubHandler{}
	handler := NewHandler("/metrics", stub)

	request := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if stub.called {
		t.Fatal("delegate handler must not be called for unsupported method")
	}

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusMethodNotAllowed,
		)
	}

	if recorder.Body.String() != "method not allowed\n" {
		t.Fatalf(
			"unexpected body: got %q, want %q",
			recorder.Body.String(),
			"method not allowed\n",
		)
	}
}

func TestHandler_NameAndPath(t *testing.T) {
	handler := NewHandler("/custom-metrics", &stubHandler{})

	if handler.Name() != Name {
		t.Fatalf(
			"unexpected name: got %q, want %q",
			handler.Name(),
			Name,
		)
	}

	if handler.Path() != "/custom-metrics" {
		t.Fatalf(
			"unexpected path: got %q, want %q",
			handler.Path(),
			"/custom-metrics",
		)
	}
}
