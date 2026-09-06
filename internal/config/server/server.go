package server

import "simple-jwt-authenticator/internal/config"

// HTTPServer contains long-running HTTP server settings.
type HTTPServer struct {
	Host              string          `yaml:"host"`
	Port              int             `yaml:"port"`
	ReadTimeout       config.Duration `yaml:"read_timeout"`
	ReadHeaderTimeout config.Duration `yaml:"read_header_timeout"`
	WriteTimeout      config.Duration `yaml:"write_timeout"`
	IdleTimeout       config.Duration `yaml:"idle_timeout"`
	ShutdownTimeout   config.Duration `yaml:"shutdown_timeout"`
	MaxHeaderBytes    int             `yaml:"max_header_bytes"`
}
