package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler_GetReturns200OK(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, Path, nil)
	recorder := httptest.NewRecorder()

	NewHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusOK,
		)
	}

	if recorder.Body.String() != "ok\n" {
		t.Fatalf(
			"unexpected body: got %q, want %q",
			recorder.Body.String(),
			"ok\n",
		)
	}
}

func TestHandler_PostNotAllowed(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, Path, nil)
	recorder := httptest.NewRecorder()

	NewHandler().ServeHTTP(recorder, request)

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
	handler := NewHandler()

	if handler.Name() != Name {
		t.Fatalf(
			"unexpected name: got %q, want %q",
			handler.Name(),
			Name,
		)
	}

	if handler.Path() != Path {
		t.Fatalf(
			"unexpected path: got %q, want %q",
			handler.Path(),
			Path,
		)
	}
}
