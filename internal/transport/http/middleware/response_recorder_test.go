package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseRecorder_UsesExplicitStatus(
	t *testing.T,
) {
	response := httptest.NewRecorder()

	recorder := newResponseRecorder(
		response,
	)

	recorder.WriteHeader(
		http.StatusCreated,
	)

	if got := recorder.Status(); got != http.StatusCreated {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			got,
			http.StatusCreated,
		)
	}

	if response.Code != http.StatusCreated {
		t.Fatalf(
			"unexpected forwarded status: got %d, want %d",
			response.Code,
			http.StatusCreated,
		)
	}
}

func TestResponseRecorder_UsesImplicit200OnWrite(
	t *testing.T,
) {
	response := httptest.NewRecorder()

	recorder := newResponseRecorder(
		response,
	)

	_, err := recorder.Write(
		[]byte("ok"),
	)
	if err != nil {
		t.Fatalf(
			"write response: %v",
			err,
		)
	}

	if got := recorder.Status(); got != http.StatusOK {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			got,
			http.StatusOK,
		)
	}
}

func TestResponseRecorder_DefaultsTo200WhenNothingWritten(
	t *testing.T,
) {
	response := httptest.NewRecorder()

	recorder := newResponseRecorder(
		response,
	)

	if got := recorder.Status(); got != http.StatusOK {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			got,
			http.StatusOK,
		)
	}
}

func TestResponseRecorder_KeepsFirstStatus(
	t *testing.T,
) {
	response := httptest.NewRecorder()

	recorder := newResponseRecorder(
		response,
	)

	recorder.WriteHeader(
		http.StatusCreated,
	)

	recorder.WriteHeader(
		http.StatusInternalServerError,
	)

	if got := recorder.Status(); got != http.StatusCreated {
		t.Fatalf(
			"unexpected status: got %d, want first status %d",
			got,
			http.StatusCreated,
		)
	}
}

func TestResponseRecorder_UnwrapReturnsOriginalWriter(
	t *testing.T,
) {
	response := httptest.NewRecorder()

	recorder := newResponseRecorder(
		response,
	)

	if got := recorder.Unwrap(); got != response {
		t.Fatalf(
			"unexpected unwrapped writer: got %T, want original %T",
			got,
			response,
		)
	}
}
