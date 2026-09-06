package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token/claim"
	claimparser "simple-jwt-authenticator/internal/token/claim/parser"
)

func TestTokenValidateCommand_ForwardsAuthenticationRequestAndPrintsIdentity(
	t *testing.T,
) {
	identity := authentication.Identity{
		Subject:  "camera-front",
		Username: "front",
		Email:    "front@example.com",
	}

	validate := &fakeValidate{
		identity: identity,
	}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	stdout, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
	)
	if err != nil {
		t.Fatalf(
			"token validate returned error: %v",
			err,
		)
	}

	if !validate.called {
		t.Fatal(
			"TokenValidate.Validate was not called",
		)
	}

	if validate.gotConfig != "/path/to/config.yaml" {
		t.Fatalf(
			"config path = %q, want %q",
			validate.gotConfig,
			"/path/to/config.yaml",
		)
	}

	if validate.gotRequest.Credential.Value != "jwt-value" {
		t.Fatalf(
			"credential value = %q, want %q",
			validate.gotRequest.Credential.Value,
			"jwt-value",
		)
	}

	if validate.gotRequest.ClaimExpression != nil {
		t.Fatal(
			"claim expression != nil, want nil when flag is omitted",
		)
	}

	expectedOutput, err := json.MarshalIndent(
		identity,
		"",
		"  ",
	)
	if err != nil {
		t.Fatalf(
			"failed to marshal expected output: %v",
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

func TestTokenValidateCommand_ParsesAndForwardsClaimExpression(
	t *testing.T,
) {
	validate := &fakeValidate{
		identity: authentication.Identity{
			Subject: "camera-front",
		},
	}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	const expression = `
		(subject == "camera-front" || subject == "camera-back") &&
		audience == "frigate"
	`

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
		"--claim-expression",
		expression,
	)
	if err != nil {
		t.Fatalf(
			"token validate returned error: %v",
			err,
		)
	}

	if !validate.called {
		t.Fatal(
			"TokenValidate.Validate was not called",
		)
	}

	if validate.gotRequest.ClaimExpression == nil {
		t.Fatal(
			"claim expression = nil, want parsed expression",
		)
	}

	if !claim.Evaluate(
		validate.gotRequest.ClaimExpression,
		claim.Claims{
			Subject: "camera-front",
			Audience: []string{
				"frigate",
			},
		},
	) {
		t.Fatal(
			"forwarded claim expression rejected matching claims",
		)
	}

	if claim.Evaluate(
		validate.gotRequest.ClaimExpression,
		claim.Claims{
			Subject: "camera-garage",
			Audience: []string{
				"frigate",
			},
		},
	) {
		t.Fatal(
			"forwarded claim expression accepted non-matching claims",
		)
	}
}

func TestTokenValidateCommand_RejectsMalformedClaimExpressionBeforeValidation(
	t *testing.T,
) {
	validate := &fakeValidate{}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
		"--claim-expression",
		`subject ==`,
	)
	if err == nil {
		t.Fatal(
			"expected claim expression parsing error",
		)
	}

	if validate.called {
		t.Fatal(
			"TokenValidate.Validate must not be called for malformed claim expression",
		)
	}

	if !errors.Is(
		err,
		claimparser.ErrSyntax,
	) {
		t.Fatalf(
			"error = %v, want claimparser.ErrSyntax",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		"parse --claim-expression",
	) {
		t.Fatalf(
			"error = %q, want parse --claim-expression context",
			err,
		)
	}
}

func TestTokenValidateCommand_RejectsInvalidClaimNameBeforeValidation(
	t *testing.T,
) {
	validate := &fakeValidate{}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
		"--claim-expression",
		`unknown == "value"`,
	)
	if err == nil {
		t.Fatal(
			"expected invalid claim name error",
		)
	}

	if validate.called {
		t.Fatal(
			"TokenValidate.Validate must not be called for invalid claim name",
		)
	}

	if !errors.Is(
		err,
		claim.ErrInvalidName,
	) {
		t.Fatalf(
			"error = %v, want claim.ErrInvalidName",
			err,
		)
	}
}

func TestTokenValidateCommand_RejectsInvalidRegexBeforeValidation(
	t *testing.T,
) {
	validate := &fakeValidate{}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
		"--claim-expression",
		`subject ~= "["`,
	)
	if err == nil {
		t.Fatal(
			"expected invalid regex error",
		)
	}

	if validate.called {
		t.Fatal(
			"TokenValidate.Validate must not be called for invalid regex",
		)
	}

	if !errors.Is(
		err,
		claim.ErrInvalidRegex,
	) {
		t.Fatalf(
			"error = %v, want claim.ErrInvalidRegex",
			err,
		)
	}
}

func TestTokenValidateCommand_WhitespaceOnlyClaimExpressionIsRejected(
	t *testing.T,
) {
	validate := &fakeValidate{}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
		"--claim-expression",
		"   ",
	)
	if err == nil {
		t.Fatal(
			"expected whitespace-only claim expression error",
		)
	}

	if validate.called {
		t.Fatal(
			"TokenValidate.Validate must not be called for whitespace-only claim expression",
		)
	}

	if !errors.Is(
		err,
		claimparser.ErrSyntax,
	) {
		t.Fatalf(
			"error = %v, want claimparser.ErrSyntax",
			err,
		)
	}
}

func TestTokenValidateCommand_ExplicitEmptyClaimExpressionAddsNoPolicy(
	t *testing.T,
) {
	validate := &fakeValidate{
		identity: authentication.Identity{
			Subject: "camera-front",
		},
	}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
		"--claim-expression",
		"",
	)
	if err != nil {
		t.Fatalf(
			"token validate returned error: %v",
			err,
		)
	}

	if !validate.called {
		t.Fatal(
			"TokenValidate.Validate was not called",
		)
	}

	if validate.gotRequest.ClaimExpression != nil {
		t.Fatal(
			"claim expression != nil, want nil for explicit empty value",
		)
	}
}

func TestTokenValidateCommand_RequiresMandatoryFlags(
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
				"validate",
				"--token",
				"jwt-value",
			},
		},
		{
			name: "missing token",
			args: []string{
				"token",
				"validate",
				"--config",
				"/path/to/config.yaml",
			},
		},
		{
			name: "missing both",
			args: []string{
				"token",
				"validate",
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				validate := &fakeValidate{}

				app := newTestApp(
					&fakeConfigValidate{},
					&fakeGenerate{},
					validate,
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

				if validate.called {
					t.Fatal(
						"TokenValidate.Validate must not be called when required flags are missing",
					)
				}
			},
		)
	}
}

func TestTokenValidateCommand_RejectsPositionalArgumentsBeforeValidation(
	t *testing.T,
) {
	validate := &fakeValidate{}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
		"unexpected-argument",
	)
	if err == nil {
		t.Fatal(
			"expected positional argument error",
		)
	}

	if validate.called {
		t.Fatal(
			"TokenValidate.Validate must not be called when positional arguments are present",
		)
	}
}

func TestTokenValidateCommand_WrapsValidationError(
	t *testing.T,
) {
	expectedErr := errors.New(
		"invalid token",
	)

	validate := &fakeValidate{
		err: expectedErr,
	}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		"jwt-value",
	)
	if err == nil {
		t.Fatal(
			"expected token validation error",
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
		"validate token",
	) {
		t.Fatalf(
			"error = %q, want validate token context",
			err,
		)
	}
}

func TestTokenValidateCommand_DoesNotIncludeCredentialInValidationError(
	t *testing.T,
) {
	const tokenValue = "secret-jwt-value-that-must-not-leak"

	validate := &fakeValidate{
		err: errors.New(
			"invalid token",
		),
	}

	app := newTestApp(
		&fakeConfigValidate{},
		&fakeGenerate{},
		validate,
	)

	_, _, err := runApp(
		t,
		app,
		"token",
		"validate",
		"--config",
		"/path/to/config.yaml",
		"--token",
		tokenValue,
	)
	if err == nil {
		t.Fatal(
			"expected token validation error",
		)
	}

	if strings.Contains(
		err.Error(),
		tokenValue,
	) {
		t.Fatalf(
			"validation error contains credential value: %q",
			err,
		)
	}
}

func TestTokenValidateCommand_ForwardsCommandContext(
	t *testing.T,
) {
	type contextKey string

	const key contextKey = "test-key"

	expectedContext := context.WithValue(
		context.Background(),
		key,
		"test-value",
	)

	validate := &fakeValidate{
		identity: authentication.Identity{
			Subject: "camera-front",
		},
	}

	command := newTokenValidateCommand(
		validate,
	)

	stdout := &bytes.Buffer{}

	err := runCommand(
		expectedContext,
		t,
		command,
		[]string{
			"--config",
			"/path/to/config.yaml",
			"--token",
			"jwt-value",
		},
		stdout,
	)
	if err != nil {
		t.Fatalf(
			"command returned error: %v",
			err,
		)
	}

	if !validate.called {
		t.Fatal(
			"TokenValidate.Validate was not called",
		)
	}

	if validate.gotContext == nil {
		t.Fatal(
			"Validate context = nil",
		)
	}

	if got := validate.gotContext.Value(key); got != "test-value" {
		t.Fatalf(
			"context value = %v, want %q",
			got,
			"test-value",
		)
	}
}

func TestTokenValidateCommand_ReturnsOutputError(
	t *testing.T,
) {
	expectedErr := errors.New(
		"stdout failed",
	)

	validate := &fakeValidate{
		identity: authentication.Identity{
			Subject: "camera-front",
		},
	}

	command := newTokenValidateCommand(
		validate,
	)

	err := runCommand(
		context.Background(),
		t,
		command,
		[]string{
			"--config",
			"/path/to/config.yaml",
			"--token",
			"jwt-value",
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

	if !validate.called {
		t.Fatal(
			"TokenValidate.Validate was not called",
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
		"write validated identity",
	) {
		t.Fatalf(
			"error = %q, want write validated identity context",
			err,
		)
	}
}
