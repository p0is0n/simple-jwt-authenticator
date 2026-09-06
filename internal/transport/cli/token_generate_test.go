package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

func TestTokenGenerateCommand_ForwardsGenerationRequest(
	t *testing.T,
) {
	serializedToken := token.SerializedToken{
		Value: token.Value(
			"signed-token",
		),
		Claims: claim.Claims{
			Subject:  "camera-front",
			Username: "front",
			Email:    "front@example.com",
			Audience: []string{
				"frigate",
				"home-assistant",
			},
		},
	}

	generate := &fakeGenerate{
		token: serializedToken,
	}

	app := newTestApp(
		&fakeConfigValidate{},
		generate,
		&fakeValidate{},
	)

	stdout, _, err := runApp(
		t,
		app,
		"token",
		"generate",
		"--config",
		"/path/to/config.yaml",
		"--subject",
		"camera-front",
		"--username",
		"front",
		"--email",
		"front@example.com",
		"--audience",
		"frigate,home-assistant",
		"--ttl",
		"2h",
	)
	if err != nil {
		t.Fatalf(
			"token generate returned error: %v",
			err,
		)
	}

	if !generate.called {
		t.Fatal(
			"TokenGenerate.Generate was not called",
		)
	}

	if generate.gotConfig != "/path/to/config.yaml" {
		t.Fatalf(
			"config path = %q, want %q",
			generate.gotConfig,
			"/path/to/config.yaml",
		)
	}

	if generate.gotRequest.Subject != "camera-front" {
		t.Fatalf(
			"subject = %q, want %q",
			generate.gotRequest.Subject,
			"camera-front",
		)
	}

	if generate.gotRequest.Username != "front" {
		t.Fatalf(
			"username = %q, want %q",
			generate.gotRequest.Username,
			"front",
		)
	}

	if generate.gotRequest.Email != "front@example.com" {
		t.Fatalf(
			"email = %q, want %q",
			generate.gotRequest.Email,
			"front@example.com",
		)
	}

	expectedAudience := []string{
		"frigate",
		"home-assistant",
	}

	if len(generate.gotRequest.Audience) != len(expectedAudience) {
		t.Fatalf(
			"audience = %#v, want %#v",
			generate.gotRequest.Audience,
			expectedAudience,
		)
	}

	for index := range expectedAudience {
		if generate.gotRequest.Audience[index] != expectedAudience[index] {
			t.Fatalf(
				"audience[%d] = %q, want %q",
				index,
				generate.gotRequest.Audience[index],
				expectedAudience[index],
			)
		}
	}

	if generate.gotRequest.TTL == nil {
		t.Fatal(
			"TTL = nil, want explicit value",
		)
	}

	if *generate.gotRequest.TTL != 2*time.Hour {
		t.Fatalf(
			"TTL = %s, want %s",
			*generate.gotRequest.TTL,
			2*time.Hour,
		)
	}

	expectedOutput, err := json.MarshalIndent(
		serializedToken,
		"",
		"  ",
	)
	if err != nil {
		t.Fatalf(
			"marshal expected output: %v",
			err,
		)
	}

	expectedOutput = append(
		expectedOutput,
		'\n',
	)

	if stdout != string(expectedOutput) {
		t.Fatalf(
			"stdout = %q, want %q",
			stdout,
			expectedOutput,
		)
	}
}

func TestTokenGenerateCommand_OmittedTTLOmitsPointer(
	t *testing.T,
) {
	generate := &fakeGenerate{
		token: testSerializedToken(),
	}

	app := newTestApp(
		&fakeConfigValidate{},
		generate,
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"generate",
		"--config",
		"/path/to/config.yaml",
		"--subject",
		"camera-front",
	)
	if err != nil {
		t.Fatalf(
			"token generate returned error: %v",
			err,
		)
	}

	if generate.gotRequest.TTL != nil {
		t.Fatalf(
			"TTL = %v, want nil",
			generate.gotRequest.TTL,
		)
	}
}

func TestTokenGenerateCommand_ExplicitZeroTTLIsPreserved(
	t *testing.T,
) {
	generate := &fakeGenerate{
		token: testSerializedToken(),
	}

	app := newTestApp(
		&fakeConfigValidate{},
		generate,
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"generate",
		"--config",
		"/path/to/config.yaml",
		"--subject",
		"camera-front",
		"--ttl",
		"0s",
	)
	if err != nil {
		t.Fatalf(
			"token generate returned error: %v",
			err,
		)
	}

	if generate.gotRequest.TTL == nil {
		t.Fatal(
			"TTL = nil, want explicit zero value",
		)
	}

	if *generate.gotRequest.TTL != 0 {
		t.Fatalf(
			"TTL = %s, want 0s",
			*generate.gotRequest.TTL,
		)
	}
}

func TestTokenGenerateCommand_NegativeTTLIsForwardedForSemanticValidation(
	t *testing.T,
) {
	generate := &fakeGenerate{
		token: testSerializedToken(),
	}

	app := newTestApp(
		&fakeConfigValidate{},
		generate,
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"generate",
		"--config",
		"/path/to/config.yaml",
		"--subject",
		"camera-front",
		"--ttl",
		"-1h",
	)
	if err != nil {
		t.Fatalf(
			"token generate returned error: %v",
			err,
		)
	}

	if !generate.called {
		t.Fatal(
			"TokenGenerate.Generate was not called",
		)
	}

	if generate.gotRequest.TTL == nil {
		t.Fatal(
			"TTL = nil, want explicit negative value",
		)
	}

	if *generate.gotRequest.TTL != -time.Hour {
		t.Fatalf(
			"TTL = %s, want %s",
			*generate.gotRequest.TTL,
			-time.Hour,
		)
	}
}

func TestTokenGenerateCommand_RejectsInvalidTTLBeforeGeneration(
	t *testing.T,
) {
	generate := &fakeGenerate{}

	app := newTestApp(
		&fakeConfigValidate{},
		generate,
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"generate",
		"--config",
		"/path/to/config.yaml",
		"--subject",
		"camera-front",
		"--ttl",
		"not-a-duration",
	)
	if err == nil {
		t.Fatal(
			"expected invalid TTL error",
		)
	}

	if generate.called {
		t.Fatal(
			"TokenGenerate.Generate must not be called for invalid TTL",
		)
	}

	if !strings.Contains(
		err.Error(),
		"parse --ttl",
	) {
		t.Fatalf(
			"error = %q, want parse --ttl context",
			err,
		)
	}
}

func TestTokenGenerateCommand_RequiresMandatoryFlags(
	t *testing.T,
) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing config",
			args: []string{
				"token",
				"generate",
				"--subject",
				"camera-front",
			},
		},
		{
			name: "missing subject",
			args: []string{
				"token",
				"generate",
				"--config",
				"/path/to/config.yaml",
			},
		},
		{
			name: "missing both",
			args: []string{
				"token",
				"generate",
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				generate := &fakeGenerate{}

				app := newTestApp(
					&fakeConfigValidate{},
					generate,
					&fakeValidate{},
				)

				_, _, err := runApp(
					t,
					app,
					test.args...,
				)
				if err == nil {
					t.Fatal(
						"expected required flag error",
					)
				}

				if generate.called {
					t.Fatal(
						"TokenGenerate.Generate must not be called when required flags are missing",
					)
				}
			},
		)
	}
}

func TestTokenGenerateCommand_RejectsPositionalArgumentsBeforeGeneration(
	t *testing.T,
) {
	generate := &fakeGenerate{}

	app := newTestApp(
		&fakeConfigValidate{},
		generate,
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"generate",
		"--config",
		"/path/to/config.yaml",
		"--subject",
		"camera-front",
		"unexpected-argument",
	)
	if err == nil {
		t.Fatal(
			"expected positional argument error",
		)
	}

	if generate.called {
		t.Fatal(
			"TokenGenerate.Generate must not be called when positional arguments are present",
		)
	}
}

func TestTokenGenerateCommand_WrapsGenerationError(
	t *testing.T,
) {
	expectedErr := errors.New(
		"signing failed",
	)

	generate := &fakeGenerate{
		err: expectedErr,
	}

	app := newTestApp(
		&fakeConfigValidate{},
		generate,
		&fakeValidate{},
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"generate",
		"--config",
		"/path/to/config.yaml",
		"--subject",
		"camera-front",
	)
	if err == nil {
		t.Fatal(
			"expected generation error",
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
		"generate token",
	) {
		t.Fatalf(
			"error = %q, want generate token context",
			err,
		)
	}
}

func TestTokenGenerateCommand_ForwardsCommandContext(
	t *testing.T,
) {
	type contextKey string

	const key contextKey = "test-key"

	expectedContext := context.WithValue(
		context.Background(),
		key,
		"test-value",
	)

	generate := &fakeGenerate{
		token: testSerializedToken(),
	}

	command := newTokenGenerateCommand(
		generate,
	)

	stdout := &bytes.Buffer{}

	err := runCommand(
		expectedContext,
		t,
		command,
		[]string{
			"--config",
			"/path/to/config.yaml",
			"--subject",
			"camera-front",
		},
		stdout,
	)
	if err != nil {
		t.Fatalf(
			"command returned error: %v",
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
			"Generate context = nil",
		)
	}

	if got := generate.gotContext.Value(key); got != "test-value" {
		t.Fatalf(
			"context value = %v, want %q",
			got,
			"test-value",
		)
	}
}

func TestTokenGenerateCommand_ReturnsOutputError(
	t *testing.T,
) {
	expectedErr := errors.New(
		"stdout failed",
	)

	generate := &fakeGenerate{
		token: testSerializedToken(),
	}

	command := newTokenGenerateCommand(
		generate,
	)

	err := runCommand(
		context.Background(),
		t,
		command,
		[]string{
			"--config",
			"/path/to/config.yaml",
			"--subject",
			"camera-front",
		},
		failingWriter{
			err: expectedErr,
		},
	)
	if err == nil {
		t.Fatal(
			"expected stdout error",
		)
	}

	if !generate.called {
		t.Fatal(
			"TokenGenerate.Generate was not called",
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
		"write generated token",
	) {
		t.Fatalf(
			"error = %q, want write generated token context",
			err,
		)
	}
}

func testSerializedToken() token.SerializedToken {
	return token.SerializedToken{
		Value: token.Value(
			"signed-token",
		),
	}
}
