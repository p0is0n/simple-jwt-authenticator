package server

import (
	"time"

	"simple-jwt-authenticator/internal/config"
)

const (
	defaultServerHost = "0.0.0.0"
	defaultServerPort = 8080

	defaultServerReadTimeout       config.Duration = config.Duration(5 * time.Second)
	defaultServerReadHeaderTimeout config.Duration = config.Duration(5 * time.Second)
	defaultServerWriteTimeout      config.Duration = config.Duration(5 * time.Second)
	defaultServerIdleTimeout       config.Duration = config.Duration(60 * time.Second)
	defaultServerShutdownTimeout   config.Duration = config.Duration(10 * time.Second)

	defaultServerMaxHeaderBytes = 1 << 20

	defaultAuthNginxHandlerEnabled = true

	defaultAuthAuthorizationHeaderExtractorEnabled = true

	defaultAuthCookieExtractorEnabled = false
	defaultAuthCookieExtractorName    = "auth_token"

	defaultJWTAlgorithm = config.JWTAlgorithmRS256

	defaultJWTClockSkew config.Duration = config.Duration(30 * time.Second)

	defaultMetricsEnabled = false
	defaultMetricsPath    = "/metrics"

	defaultLoggingLevel  = config.LogLevelInfo
	defaultLoggingFormat = config.LogFormatJSON
)

// defaultConfig returns the complete default configuration for the server
// application.
//
// Operational settings receive safe defaults so that configuration files can
// stay focused on deployment-specific policy.
//
// Security-sensitive trust policy deliberately has no operational defaults.
// The JWT verification key source, issuer, and audience must therefore be
// configured explicitly and are enforced by semantic validation.
func defaultConfig() Config {
	return Config{
		Server: HTTPServer{
			Host:              defaultServerHost,
			Port:              defaultServerPort,
			ReadTimeout:       defaultServerReadTimeout,
			ReadHeaderTimeout: defaultServerReadHeaderTimeout,
			WriteTimeout:      defaultServerWriteTimeout,
			IdleTimeout:       defaultServerIdleTimeout,
			ShutdownTimeout:   defaultServerShutdownTimeout,
			MaxHeaderBytes:    defaultServerMaxHeaderBytes,
		},
		Auth: Auth{
			Handlers: AuthHandlers{
				HTTP: AuthHTTPHandlers{
					Nginx: AuthNginxHandler{
						Enabled: defaultAuthNginxHandlerEnabled,
					},
				},
			},
			Extractors: AuthExtractors{
				HTTP: AuthHTTPExtractors{
					AuthorizationHeader: AuthAuthorizationHeaderExtractor{
						Enabled: defaultAuthAuthorizationHeaderExtractorEnabled,
					},
					Cookie: AuthCookieExtractor{
						Enabled: defaultAuthCookieExtractorEnabled,
						Name:    defaultAuthCookieExtractorName,
					},
				},
			},
		},
		JWT: config.JWTVerification{
			Algorithm: defaultJWTAlgorithm,
			ClockSkew: defaultJWTClockSkew,
		},
		Metrics: Metrics{
			Enabled: defaultMetricsEnabled,
			Path:    defaultMetricsPath,
		},
		Logging: config.Logging{
			Level:  defaultLoggingLevel,
			Format: defaultLoggingFormat,
		},
	}
}
