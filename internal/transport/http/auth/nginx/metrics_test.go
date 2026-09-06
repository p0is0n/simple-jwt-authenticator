package nginx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/metrics"
	"simple-jwt-authenticator/internal/token/validator"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

type recordingAuthRecorder struct {
	calls      int
	lastResult metrics.Result
	lastSource string
	lastReason metrics.FailureReason
}

func (r *recordingAuthRecorder) RecordAuth(
	_ context.Context,
	_ string,
	result metrics.Result,
	source string,
	reason metrics.FailureReason,
	_ time.Duration,
) {
	r.calls++
	r.lastResult = result
	r.lastSource = source
	r.lastReason = reason
}

func TestHandler_RecordsBoundedFailureLabels(t *testing.T) {
	auth := authenticatorFunc(
		func(
			_ context.Context,
			_ authentication.Request,
		) (authentication.Identity, error) {
			return authentication.Identity{},
				errors.Join(
					authentication.ErrAuthentication,
					validator.ErrExpired,
				)
		},
	)

	creds := credentialProviderFunc(
		func(_ *http.Request) (credential.Result, error) {
			return credential.Result{
				Credential: authentication.Credential{
					Value: "token",
				},
				Source: credential.Source(
					"attacker-controlled-source",
				),
				Extracted: true,
			}, nil
		},
	)

	recorder := &recordingAuthRecorder{}

	handler, err := NewHandler(
		auth,
		creds,
		testClaimExpressionProvider(),
		recorder,
		slog.New(
			slog.NewTextHandler(
				io.Discard,
				nil,
			),
		),
	)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	handler.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.calls != 1 {
		t.Fatalf(
			"unexpected recorder calls: got %d, want 1",
			recorder.calls,
		)
	}

	if recorder.lastResult != metrics.ResultFailure {
		t.Fatalf(
			"unexpected result: got %q, want %q",
			recorder.lastResult,
			metrics.ResultFailure,
		)
	}

	if recorder.lastSource != string(credential.SourceUnknown) {
		t.Fatalf(
			"unexpected source: got %q, want %q",
			recorder.lastSource,
			credential.SourceUnknown,
		)
	}

	if recorder.lastReason != metrics.ReasonExpired {
		t.Fatalf(
			"unexpected reason: got %q, want %q",
			recorder.lastReason,
			metrics.ReasonExpired,
		)
	}
}
