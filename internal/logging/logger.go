// Package logging constructs structured log/slog loggers from server
// logging configuration.
//
// The package owns translation from configuration values into slog-specific
// types. It does not perform application logging itself and does not add
// request, credential, identity, or other application-specific attributes.
package logging

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"simple-jwt-authenticator/internal/config"
)

// format is the logging-package representation of a validated output format.
//
// Keeping this type private prevents raw configuration strings from reaching
// handler construction after validation.
type format uint8

const (
	formatJSON format = iota
	formatText
)

// New constructs a *slog.Logger from server logging configuration.
//
// Both level and format are validated here even though the server
// configuration is normally validated before this package is called.
// Constructors remain internally consistent when invoked directly and do not
// silently replace unsupported values with defaults.
func New(
	logging config.Logging,
) (*slog.Logger, error) {
	level, err := parseLevel(logging.Level)
	if err != nil {
		return nil, err
	}

	outputFormat, err := parseFormat(logging.Format)
	if err != nil {
		return nil, err
	}

	handler := newHandler(
		level,
		outputFormat,
	)

	return slog.New(handler), nil
}

// parseLevel translates a configured logging level into slog's native level.
//
// Empty values are accepted as the package-level default for direct callers.
// Server configurations loaded through config/server receive the explicit
// "info" default before reaching this package.
func parseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", config.LogLevelInfo:
		return slog.LevelInfo, nil

	case config.LogLevelDebug:
		return slog.LevelDebug, nil

	case config.LogLevelWarn:
		return slog.LevelWarn, nil

	case config.LogLevelError:
		return slog.LevelError, nil

	default:
		return 0, fmt.Errorf(
			"parse logging level %q: %w",
			value,
			errUnsupportedLevel,
		)
	}
}

// parseFormat translates a configured output format into the private
// validated representation used by handler construction.
//
// Empty values are accepted as JSON for direct callers, matching the server
// configuration default.
func parseFormat(value string) (format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", config.LogFormatJSON:
		return formatJSON, nil

	case config.LogFormatText:
		return formatText, nil

	default:
		return 0, fmt.Errorf(
			"parse logging format %q: %w",
			value,
			errUnsupportedFormat,
		)
	}
}

// newHandler constructs a slog handler from already validated values.
//
// No fallback branch exists here: unsupported configuration must be rejected
// before handler construction rather than silently changing application
// behavior.
func newHandler(
	level slog.Level,
	outputFormat format,
) slog.Handler {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch outputFormat {
	case formatJSON:
		return slog.NewJSONHandler(
			os.Stdout,
			opts,
		)

	case formatText:
		return slog.NewTextHandler(
			os.Stdout,
			opts,
		)

	default:
		// outputFormat is private and can only be produced by parseFormat in
		// normal construction. Reaching this branch therefore indicates a
		// programming error rather than invalid external configuration.
		panic("logging: invalid validated format")
	}
}
