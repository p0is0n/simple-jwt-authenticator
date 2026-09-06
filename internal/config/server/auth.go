// Package server defines the configuration contract and validation pipeline
// for the HTTP server application.
package server

// Auth holds authentication handler and credential extractor configuration
// used by the HTTP server.
type Auth struct {
	Handlers   AuthHandlers   `yaml:"handlers"`
	Extractors AuthExtractors `yaml:"extractors"`
}

// AuthHandlers groups authentication handler families.
type AuthHandlers struct {
	HTTP AuthHTTPHandlers `yaml:"http"`
}

// AuthHTTPHandlers groups concrete HTTP authentication handlers.
type AuthHTTPHandlers struct {
	Nginx AuthNginxHandler `yaml:"nginx"`
}

// AuthNginxHandler configures the Nginx auth_request integration.
type AuthNginxHandler struct {
	Enabled bool `yaml:"enabled"`
}

// AuthExtractors groups credential extractor families.
type AuthExtractors struct {
	HTTP AuthHTTPExtractors `yaml:"http"`
}

// AuthHTTPExtractors groups supported HTTP credential extractors.
type AuthHTTPExtractors struct {
	AuthorizationHeader AuthAuthorizationHeaderExtractor `yaml:"authorization_header"`
	Cookie              AuthCookieExtractor              `yaml:"cookie"`
}

// AuthAuthorizationHeaderExtractor configures Bearer credential extraction
// from the Authorization header.
type AuthAuthorizationHeaderExtractor struct {
	Enabled bool `yaml:"enabled"`
}

// AuthCookieExtractor configures authentication cookie extraction.
type AuthCookieExtractor struct {
	Enabled bool   `yaml:"enabled"`
	Name    string `yaml:"name"`
}
