package server

import "simple-jwt-authenticator/internal/config"

// Config is the complete configuration contract for the long-running
// authentication server.
//
// Signing material and token-generation policy deliberately do not exist in
// this schema.
type Config struct {
	Server  HTTPServer             `yaml:"server"`
	Auth    Auth                   `yaml:"auth"`
	JWT     config.JWTVerification `yaml:"jwt"`
	Metrics Metrics                `yaml:"metrics"`
	Logging config.Logging         `yaml:"logging"`
}
