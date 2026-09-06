package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubHandler is a minimal common Handler for router tests.
type stubHandler struct {
	name string
	path string
}

func (h stubHandler) Name() string { return h.name }
func (h stubHandler) Path() string { return h.path }
func (h stubHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// stubAuthHandler is a minimal AuthHandler for router tests.
type stubAuthHandler struct {
	stubHandler
	adapter string
}

func (h stubAuthHandler) Adapter() string { return h.adapter }

func TestRouter_AddHandlerRegistersRoute(t *testing.T) {
	router := NewRouter()
	router.AddHandler(stubHandler{name: "health", path: "/healthz"})

	recorder := httptest.NewRecorder()
	router.Handler().ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/healthz", nil),
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"unexpected status: got %d",
			recorder.Code,
		)
	}
}

func TestRouter_AddAuthHandlerRegistersRoute(t *testing.T) {
	router := NewRouter()
	router.AddAuthHandler(stubAuthHandler{
		stubHandler: stubHandler{name: "nginx", path: "/auth/nginx"},
		adapter:     "http-auth-nginx",
	})

	recorder := httptest.NewRecorder()
	router.Handler().ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/auth/nginx", nil),
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"unexpected status: got %d",
			recorder.Code,
		)
	}
}

func TestRouter_UnmatchedRouteReturns404(t *testing.T) {
	router := NewRouter()
	router.AddHandler(stubHandler{name: "health", path: "/healthz"})

	recorder := httptest.NewRecorder()
	router.Handler().ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/unknown", nil),
	)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusNotFound,
		)
	}
}
