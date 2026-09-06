package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	stdhttp "net/http"

	serverconfig "simple-jwt-authenticator/internal/config/server"
)

// Server owns construction and lifecycle of the standard net/http server.
// The composition root supplies configuration, the handler, and a logger.
type Server struct {
	server          *stdhttp.Server
	shutdownTimeout time.Duration
	logger          *slog.Logger
}

// NewServer constructs a Server from configuration. It configures all
// security-relevant timeouts explicitly and uses net.JoinHostPort to
// preserve IPv6 correctness.
func NewServer(
	serverConfig serverconfig.HTTPServer,
	handler stdhttp.Handler,
	logger *slog.Logger,
) (*Server, error) {
	address := net.JoinHostPort(
		serverConfig.Host,
		strconv.Itoa(serverConfig.Port),
	)

	httpServer := &stdhttp.Server{
		Addr:              address,
		Handler:           handler,
		ReadTimeout:       serverConfig.ReadTimeout.Std(),
		ReadHeaderTimeout: serverConfig.ReadHeaderTimeout.Std(),
		WriteTimeout:      serverConfig.WriteTimeout.Std(),
		IdleTimeout:       serverConfig.IdleTimeout.Std(),
		MaxHeaderBytes:    serverConfig.MaxHeaderBytes,
	}

	return &Server{
		server:          httpServer,
		shutdownTimeout: serverConfig.ShutdownTimeout.Std(),
		logger:          logger,
	}, nil
}

// Run starts the server and blocks until the context is cancelled, then
// shuts down gracefully within the configured shutdown timeout.
func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf(
			"listen on %s: %w",
			s.server.Addr,
			err,
		)
	}

	s.logger.InfoContext(
		ctx,
		"server listening",
		"address",
		s.server.Addr,
	)

	serveErr := make(chan error, 1)

	go func() {
		// This goroutine's lifetime is tied to the server. It exits when
		// Serve returns (on shutdown or error), so it does not leak.
		serveErr <- s.server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		return s.shutdown()

	case err := <-serveErr:
		if err != nil && !errors.Is(err, stdhttp.ErrServerClosed) {
			return fmt.Errorf(
				"serve: %w",
				err,
			)
		}

		return nil
	}
}

// shutdown stops the server gracefully within the configured timeout.
func (s *Server) shutdown() error {
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		s.shutdownTimeout,
	)
	defer cancel()

	s.logger.InfoContext(
		shutdownCtx,
		"server shutting down",
	)

	if err := s.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf(
			"shutdown: %w",
			err,
		)
	}

	return nil
}

// Address returns the configured listen address.
func (s *Server) Address() string {
	return s.server.Addr
}
