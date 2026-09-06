package server

// Metrics contains Prometheus HTTP endpoint configuration.
type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}
