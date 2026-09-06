package cli

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/spf13/cobra"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token"
)

type fakeGenerate struct {
	called     bool
	gotContext context.Context
	gotConfig  string
	gotRequest token.GenerateRequest

	token token.SerializedToken
	err   error
}

func (f *fakeGenerate) Generate(
	ctx context.Context,
	configPath string,
	request token.GenerateRequest,
) (token.SerializedToken, error) {
	f.called = true
	f.gotContext = ctx
	f.gotConfig = configPath
	f.gotRequest = request

	return f.token, f.err
}

type fakeValidate struct {
	called     bool
	gotContext context.Context
	gotConfig  string
	gotRequest authentication.Request

	identity authentication.Identity
	err      error
}

func (f *fakeValidate) Validate(
	ctx context.Context,
	configPath string,
	request authentication.Request,
) (authentication.Identity, error) {
	f.called = true
	f.gotContext = ctx
	f.gotConfig = configPath
	f.gotRequest = request

	return f.identity, f.err
}

type fakeConfigValidate struct {
	called  bool
	gotPath string
	gotMode ConfigValidationMode

	err error
}

func (f *fakeConfigValidate) Validate(
	path string,
	mode ConfigValidationMode,
) error {
	f.called = true
	f.gotPath = path
	f.gotMode = mode

	return f.err
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write(
	_ []byte,
) (int, error) {
	return 0, w.err
}

func newTestApp(
	configValidate ConfigValidate,
	generate TokenGenerate,
	validate TokenValidate,
) *App {
	return New(
		configValidate,
		generate,
		validate,
	)
}

func runApp(
	t *testing.T,
	app *App,
	args ...string,
) (string, string, error) {
	t.Helper()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	err := app.Execute(
		context.Background(),
		args,
		stdout,
		stderr,
	)

	return stdout.String(), stderr.String(), err
}

func runCommand(
	commandContext context.Context,
	t *testing.T,
	command *cobra.Command,
	commandArgs []string,
	stdout io.Writer,
) error {
	t.Helper()

	if commandContext != nil {
		command.SetContext(
			commandContext,
		)
	}

	if stdout != nil {
		command.SetOut(
			stdout,
		)
	}

	command.SetErr(
		&bytes.Buffer{},
	)

	command.SetArgs(
		commandArgs,
	)

	return command.Execute()
}

func TestApp_UnknownCommandReturnsError(
	t *testing.T,
) {
	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"unknown-command",
	)
	if err == nil {
		t.Fatal(
			"expected unknown command to fail",
		)
	}
}

func TestApp_ContextPropagatesToCommandBehavior(
	t *testing.T,
) {
	type contextKey string

	const key contextKey = "test-key"

	ctx := context.WithValue(
		context.Background(),
		key,
		"test-value",
	)

	generate := &fakeGenerate{
		token: testSerializedToken(),
	}

	app := newTestApp(
		&fakeConfigValidate{},
		generate,
		&fakeValidate{},
	)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	err := app.Execute(
		ctx,
		[]string{
			"token",
			"generate",
			"--config",
			"/path/to/config.yaml",
			"--subject",
			"test-subject",
		},
		stdout,
		stderr,
	)
	if err != nil {
		t.Fatalf(
			"Execute() error = %v, want nil",
			err,
		)
	}

	if !generate.called {
		t.Fatal(
			"TokenGenerate.Generate was not called",
		)
	}

	if generate.gotContext == nil {
		t.Fatal(
			"Generate() context = nil, want propagated context",
		)
	}

	if got := generate.gotContext.Value(key); got != "test-value" {
		t.Fatalf(
			"Generate() context value = %v, want %q",
			got,
			"test-value",
		)
	}
}

func TestApp_NilContextRejected(
	t *testing.T,
) {
	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		&fakeValidate{},
	)

	var nilContext context.Context
	err := app.Execute(
		nilContext,
		nil,
		&bytes.Buffer{},
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal(
			"Execute() error = nil, want error for nil context",
		)
	}
}
