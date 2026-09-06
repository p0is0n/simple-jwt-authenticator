package logging

import (
	"errors"
	"log/slog"
	"testing"

	"simple-jwt-authenticator/internal/config"
)

func TestNew_JSONInfo(t *testing.T) {
	logger, err := New(
		config.Logging{
			Level:  config.LogLevelInfo,
			Format: config.LogFormatJSON,
		},
	)
	if err != nil {
		t.Fatalf(
			"New() error = %v, want nil",
			err,
		)
	}

	if logger == nil {
		t.Fatal(
			"New() logger = nil, want non-nil",
		)
	}
}

func TestNew_TextDebug(t *testing.T) {
	logger, err := New(
		config.Logging{
			Level:  config.LogLevelDebug,
			Format: config.LogFormatText,
		},
	)
	if err != nil {
		t.Fatalf(
			"New() error = %v, want nil",
			err,
		)
	}

	if logger == nil {
		t.Fatal(
			"New() logger = nil, want non-nil",
		)
	}
}

func TestNew_UnsupportedLevelRejected(t *testing.T) {
	logger, err := New(
		config.Logging{
			Level:  "verbose",
			Format: config.LogFormatJSON,
		},
	)

	if !errors.Is(
		err,
		errUnsupportedLevel,
	) {
		t.Fatalf(
			"New() error = %v, want errUnsupportedLevel",
			err,
		)
	}

	if logger != nil {
		t.Fatalf(
			"New() logger = %+v, want nil",
			logger,
		)
	}
}

func TestNew_UnsupportedFormatRejected(t *testing.T) {
	logger, err := New(
		config.Logging{
			Level:  config.LogLevelInfo,
			Format: "yaml",
		},
	)

	if !errors.Is(
		err,
		errUnsupportedFormat,
	) {
		t.Fatalf(
			"New() error = %v, want errUnsupportedFormat",
			err,
		)
	}

	if logger != nil {
		t.Fatalf(
			"New() logger = %+v, want nil",
			logger,
		)
	}
}

func TestNew_EmptyValuesUseDefaults(t *testing.T) {
	logger, err := New(config.Logging{})
	if err != nil {
		t.Fatalf(
			"New() error = %v, want nil",
			err,
		)
	}

	if logger == nil {
		t.Fatal(
			"New() logger = nil, want non-nil",
		)
	}
}

func TestParseLevel_AllSupportedValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  slog.Level
	}{
		{
			name:  "debug",
			value: config.LogLevelDebug,
			want:  slog.LevelDebug,
		},
		{
			name:  "info",
			value: config.LogLevelInfo,
			want:  slog.LevelInfo,
		},
		{
			name:  "warn",
			value: config.LogLevelWarn,
			want:  slog.LevelWarn,
		},
		{
			name:  "error",
			value: config.LogLevelError,
			want:  slog.LevelError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseLevel(test.value)
			if err != nil {
				t.Fatalf(
					"parseLevel() error = %v, want nil",
					err,
				)
			}

			if got != test.want {
				t.Fatalf(
					"parseLevel() = %v, want %v",
					got,
					test.want,
				)
			}
		})
	}
}

func TestParseLevel_NormalizesInput(t *testing.T) {
	got, err := parseLevel(
		" DEBUG ",
	)
	if err != nil {
		t.Fatalf(
			"parseLevel() error = %v, want nil",
			err,
		)
	}

	if got != slog.LevelDebug {
		t.Fatalf(
			"parseLevel() = %v, want %v",
			got,
			slog.LevelDebug,
		)
	}
}

func TestParseFormat_AllSupportedValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  format
	}{
		{
			name:  "json",
			value: config.LogFormatJSON,
			want:  formatJSON,
		},
		{
			name:  "text",
			value: config.LogFormatText,
			want:  formatText,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseFormat(test.value)
			if err != nil {
				t.Fatalf(
					"parseFormat() error = %v, want nil",
					err,
				)
			}

			if got != test.want {
				t.Fatalf(
					"parseFormat() = %v, want %v",
					got,
					test.want,
				)
			}
		})
	}
}

func TestParseFormat_NormalizesInput(t *testing.T) {
	got, err := parseFormat(
		" TEXT ",
	)
	if err != nil {
		t.Fatalf(
			"parseFormat() error = %v, want nil",
			err,
		)
	}

	if got != formatText {
		t.Fatalf(
			"parseFormat() = %v, want %v",
			got,
			formatText,
		)
	}
}

func TestParseLevel_EmptyUsesInfo(t *testing.T) {
	got, err := parseLevel("")
	if err != nil {
		t.Fatalf(
			"parseLevel() error = %v, want nil",
			err,
		)
	}

	if got != slog.LevelInfo {
		t.Fatalf(
			"parseLevel() = %v, want %v",
			got,
			slog.LevelInfo,
		)
	}
}

func TestParseFormat_EmptyUsesJSON(t *testing.T) {
	got, err := parseFormat("")
	if err != nil {
		t.Fatalf(
			"parseFormat() error = %v, want nil",
			err,
		)
	}

	if got != formatJSON {
		t.Fatalf(
			"parseFormat() = %v, want %v",
			got,
			formatJSON,
		)
	}
}
