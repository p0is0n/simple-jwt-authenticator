package cli

import (
	"time"

	"simple-jwt-authenticator/internal/config"
)

const (
	defaultJWTAlgorithm = config.JWTAlgorithmRS256

	defaultJWTClockSkew config.Duration = config.Duration(30 * time.Second)

	defaultJWTDefaultTTL config.Duration = config.Duration(time.Hour)
	defaultJWTMaxTTL     config.Duration = config.Duration(7 * 24 * time.Hour)
)

// defaultConfig returns the complete default configuration for CLI JWT
// operations.
//
// Operational JWT settings receive safe defaults. Security-sensitive key
// material and trust policy deliberately have no defaults and must be
// configured explicitly for the command that requires them.
func defaultConfig() Config {
	return Config{
		JWT: JWT{
			JWTVerification: config.JWTVerification{
				Algorithm: defaultJWTAlgorithm,
				ClockSkew: defaultJWTClockSkew,
			},
			JWTSigning: config.JWTSigning{
				DefaultTTL: defaultJWTDefaultTTL,
				MaxTTL:     defaultJWTMaxTTL,
			},
		},
	}
}
