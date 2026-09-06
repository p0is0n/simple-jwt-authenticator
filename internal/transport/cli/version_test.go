package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"simple-jwt-authenticator/internal/buildinfo"
)

func TestVersionString(
	t *testing.T,
) {
	info := buildinfo.Info{
		Version: "1.2.3",
		Commit:  "abcdef123456",
		Date:    "2026-08-31T12:00:00Z",
	}

	got := versionString(
		info,
	)

	want := "simple-jwt-authenticator 1.2.3 (commit: abcdef123456, date: 2026-08-31T12:00:00Z)\n"

	if got != want {
		t.Fatalf(
			"versionString() = %q, want %q",
			got,
			want,
		)
	}
}

func TestVersionCommand_PrintsBuildInfo(
	t *testing.T,
) {
	command := newVersionCommand()

	stdout := &bytes.Buffer{}

	err := runCommand(
		context.Background(),
		t,
		command,
		nil,
		stdout,
	)
	if err != nil {
		t.Fatalf(
			"version command returned error: %v",
			err,
		)
	}

	if !strings.HasPrefix(
		stdout.String(),
		"simple-jwt-authenticator ",
	) {
		t.Fatalf(
			"version output = %q, want simple-jwt-authenticator prefix",
			stdout.String(),
		)
	}
}

func TestVersionCommand_RejectsPositionalArguments(
	t *testing.T,
) {
	command := newVersionCommand()

	err := runCommand(
		context.Background(),
		t,
		command,
		[]string{
			"unexpected-argument",
		},
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal(
			"expected positional argument error",
		)
	}
}

func TestVersionCommand_ReturnsOutputError(
	t *testing.T,
) {
	expectedErr := errors.New(
		"stdout failed",
	)

	command := newVersionCommand()

	err := runCommand(
		context.Background(),
		t,
		command,
		nil,
		failingWriter{
			err: expectedErr,
		},
	)
	if err == nil {
		t.Fatal(
			"expected stdout error",
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

	if !strings.Contains(
		err.Error(),
		"write version information",
	) {
		t.Fatalf(
			"error = %q, want write version information context",
			err,
		)
	}
}
