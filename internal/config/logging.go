package config

// Supported logging levels and output formats.
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"

	LogFormatJSON = "json"
	LogFormatText = "text"
)

// Logging configures application logging.
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}
