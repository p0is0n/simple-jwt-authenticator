// Package http owns the HTTP transport boundary: route registration,
// common middleware composition, and server lifecycle. It consumes the
// transport-independent authentication behavior.
package http

import (
	stdhttp "net/http"
)

// Handler is the common HTTP handler contract. Each handler owns its
// stable path and name.
type Handler interface {
	Name() string
	Path() string
	stdhttp.Handler
}

// AuthHandler extends the common handler contract with an adapter
// identity. This is intentionally a marker/metadata contract for auth
// adapters and is kept distinct from AddHandler even though the current
// mux registration is identical.
type AuthHandler interface {
	Handler
	Adapter() string
}

// Router owns route registration only. It does not compose middleware and
// does not own server lifecycle.
type Router struct {
	mux *stdhttp.ServeMux
}

// NewRouter constructs an empty Router.
func NewRouter() *Router {
	return &Router{
		mux: stdhttp.NewServeMux(),
	}
}

// AddHandler registers a common handler.
func (r *Router) AddHandler(handler Handler) {
	r.mux.Handle(handler.Path(), handler)
}

// AddAuthHandler registers an auth adapter handler. Kept separate from
// AddHandler to document intent and leave room for future auth-specific
// registration policy.
func (r *Router) AddAuthHandler(handler AuthHandler) {
	r.mux.Handle(handler.Path(), handler)
}

// Handler returns the underlying handler for middleware composition.
func (r *Router) Handler() stdhttp.Handler {
	return r.mux
}
