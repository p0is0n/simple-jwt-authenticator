// Package cli contains configuration for CLI JWT operations.
package cli

import "simple-jwt-authenticator/internal/config"

// Config is the configuration contract for CLI JWT operations.
type Config struct {
	JWT JWT `yaml:"jwt"`
}

// JWT combines verification and signing capabilities required by CLI
// operations while preserving the flat public YAML structure.
type JWT struct {
	config.JWTVerification `yaml:",inline"`
	config.JWTSigning      `yaml:",inline"`
}
