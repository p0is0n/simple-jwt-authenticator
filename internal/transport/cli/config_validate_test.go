package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestConfigValidateCommand_DefaultsToServerMode(
	t *testing.T,
) {
	validate := &fakeConfigValidate{}

	app := newTestApp(
		validate,
		&fakeGenerate{},
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"config",
		"validate",
		"/path/to/config.yaml",
	)
	if err != nil {
		t.Fatalf(
			"config validate returned error: %v",
			err,
		)
	}

	if !validate.called {
		t.Fatal(
			"ConfigValidate.Validate was not called",
		)
	}

	if validate.gotPath != "/path/to/config.yaml" {
		t.Fatalf(
			"config path = %q, want %q",
			validate.gotPath,
			"/path/to/config.yaml",
		)
	}

	if validate.gotMode != ConfigValidationModeServer {
		t.Fatalf(
			"mode = %q, want %q",
			validate.gotMode,
			ConfigValidationModeServer,
		)
	}
}

func TestConfigValidateCommand_ForwardsExplicitMode(
	t *testing.T,
) {
	tests := []struct {
		name string
		mode ConfigValidationMode
	}{
		{
			name: "server",
			mode: ConfigValidationModeServer,
		},
		{
			name: "token generate",
			mode: ConfigValidationModeTokenGenerate,
		},
		{
			name: "token validate",
			mode: ConfigValidationModeTokenValidate,
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				validate := &fakeConfigValidate{}

				app := newTestApp(
					validate,
					&fakeGenerate{},
					&fakeValidate{},
				)

				_, _, err := runApp(
					t,
					app,
					"config",
					"validate",
					"--mode",
					string(test.mode),
					"/path/to/config.yaml",
				)
				if err != nil {
					t.Fatalf(
						"config validate returned error: %v",
						err,
					)
				}

				if !validate.called {
					t.Fatal(
						"ConfigValidate.Validate was not called",
					)
				}

				if validate.gotPath != "/path/to/config.yaml" {
					t.Fatalf(
						"config path = %q, want %q",
						validate.gotPath,
						"/path/to/config.yaml",
					)
				}

				if validate.gotMode != test.mode {
					t.Fatalf(
						"mode = %q, want %q",
						validate.gotMode,
						test.mode,
					)
				}
			},
		)
	}
}

func TestConfigValidateCommand_RejectsUnsupportedModeBeforeBehavior(
	t *testing.T,
) {
	validate := &fakeConfigValidate{}

	app := newTestApp(
		validate,
		&fakeGenerate{},
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"config",
		"validate",
		"--mode",
		"unsupported",
		"/path/to/config.yaml",
	)
	if err == nil {
		t.Fatal(
			"expected unsupported mode error",
		)
	}

	if validate.called {
		t.Fatal(
			"ConfigValidate.Validate must not be called for unsupported mode",
		)
	}

	if !strings.Contains(
		err.Error(),
		"unsupported configuration validation mode",
	) {
		t.Fatalf(
			"error = %q, want unsupported mode context",
			err,
		)
	}
}

func TestConfigValidateCommand_PropagatesBehaviorError(
	t *testing.T,
) {
	expectedErr := errors.New(
		"validation failed",
	)

	validate := &fakeConfigValidate{
		err: expectedErr,
	}

	app := newTestApp(
		validate,
		&fakeGenerate{},
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"config",
		"validate",
		"/path/to/config.yaml",
	)
	if err == nil {
		t.Fatal(
			"expected validation error",
		)
	}

	if !errors.Is(
		err,
		expectedErr,
	) {
		t.Fatalf(
			"error = %v, want wrapped %v",
			err,
			expectedErr,
		)
	}
}

func TestConfigValidateCommand_RequiresExactlyOnePath(
	t *testing.T,
) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing path",
			args: []string{
				"config",
				"validate",
			},
		},
		{
			name: "multiple paths",
			args: []string{
				"config",
				"validate",
				"first.yaml",
				"second.yaml",
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				validate := &fakeConfigValidate{}

				app := newTestApp(
					validate,
					&fakeGenerate{},
					&fakeValidate{},
				)

				_, _, err := runApp(
					t,
					app,
					test.args...,
				)
				if err == nil {
					t.Fatal(
						"expected argument validation error",
					)
				}

				if validate.called {
					t.Fatal(
						"ConfigValidate.Validate must not be called when arguments are invalid",
					)
				}
			},
		)
	}
}

func TestParseConfigValidationMode(
	t *testing.T,
) {
	tests := []struct {
		name    string
		value   string
		want    ConfigValidationMode
		wantErr bool
	}{
		{
			name:  "server",
			value: "server",
			want:  ConfigValidationModeServer,
		},
		{
			name:  "token generate",
			value: "token-generate",
			want:  ConfigValidationModeTokenGenerate,
		},
		{
			name:  "token validate",
			value: "token-validate",
			want:  ConfigValidationModeTokenValidate,
		},
		{
			name:    "empty",
			value:   "",
			wantErr: true,
		},
		{
			name:    "unsupported",
			value:   "unsupported",
			wantErr: true,
		},
		{
			name:    "case mismatch",
			value:   "SERVER",
			wantErr: true,
		},
		{
			name:    "leading whitespace",
			value:   " server",
			wantErr: true,
		},
		{
			name:    "trailing whitespace",
			value:   "server ",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				got, err := parseConfigValidationMode(
					test.value,
				)

				if test.wantErr {
					if err == nil {
						t.Fatalf(
							"parseConfigValidationMode(%q) error = nil, want error",
							test.value,
						)
					}

					return
				}

				if err != nil {
					t.Fatalf(
						"parseConfigValidationMode(%q) error = %v, want nil",
						test.value,
						err,
					)
				}

				if got != test.want {
					t.Fatalf(
						"parseConfigValidationMode(%q) = %q, want %q",
						test.value,
						got,
						test.want,
					)
				}
			},
		)
	}
}
