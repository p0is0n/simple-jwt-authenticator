package nginx

import (
	"context"
	"errors"
	"testing"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/validator"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want failureClassification
	}{
		{
			name: "credential missing",
			err:  credential.ErrMissingCredential,
			want: unauthorizedFailure(
				failureReasonMissingCredential,
			),
		},
		{
			name: "authentication credential missing",
			err: errors.Join(
				authentication.ErrAuthentication,
				authentication.ErrMissingCredential,
			),
			want: unauthorizedFailure(
				failureReasonMissingCredential,
			),
		},
		{
			name: "malformed credential",
			err:  credential.ErrMalformedCredential,
			want: unauthorizedFailure(
				failureReasonMalformedCredential,
			),
		},
		{
			name: "malformed token",
			err:  token.ErrMalformedToken,
			want: unauthorizedFailure(
				failureReasonMalformedToken,
			),
		},
		{
			name: "unsupported algorithm",
			err:  token.ErrUnsupportedAlgorithm,
			want: unauthorizedFailure(
				failureReasonUnsupportedAlgorithm,
			),
		},
		{
			name: "invalid signature",
			err:  token.ErrInvalidSignature,
			want: unauthorizedFailure(
				failureReasonInvalidSignature,
			),
		},
		{
			name: "expired",
			err:  validator.ErrExpired,
			want: unauthorizedFailure(
				failureReasonExpired,
			),
		},
		{
			name: "wrapped expired",
			err: errors.Join(
				authentication.ErrAuthentication,
				validator.ErrExpired,
			),
			want: unauthorizedFailure(
				failureReasonExpired,
			),
		},
		{
			name: "not active",
			err:  validator.ErrNotActive,
			want: unauthorizedFailure(
				failureReasonNotActive,
			),
		},
		{
			name: "invalid issuer",
			err:  validator.ErrInvalidIssuer,
			want: unauthorizedFailure(
				failureReasonInvalidIssuer,
			),
		},
		{
			name: "invalid audience",
			err:  validator.ErrInvalidAudience,
			want: unauthorizedFailure(
				failureReasonInvalidAudience,
			),
		},
		{
			name: "claim expression not satisfied",
			err: errors.Join(
				authentication.ErrAuthentication,
				validator.ErrClaimExpressionNotSatisfied,
			),
			want: unauthorizedFailure(
				failureReasonClaimExpressionNotSatisfied,
			),
		},
		{
			name: "missing claim",
			err:  validator.ErrMissingClaim,
			want: unauthorizedFailure(
				failureReasonInvalidClaims,
			),
		},
		{
			name: "invalid identity",
			err: errors.Join(
				authentication.ErrAuthentication,
				authentication.ErrInvalidIdentity,
			),
			want: unauthorizedFailure(
				failureReasonInvalidClaims,
			),
		},
		{
			name: "bare authentication sentinel",
			err:  authentication.ErrAuthentication,
			want: failureClassification{
				disposition: failureDispositionInternal,
				reason:      failureReasonInternal,
			},
		},
		{
			name: "unknown error joined with authentication sentinel",
			err: errors.Join(
				authentication.ErrAuthentication,
				errors.New("unexpected internal failure"),
			),
			want: failureClassification{
				disposition: failureDispositionInternal,
				reason:      failureReasonInternal,
			},
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			want: failureClassification{
				disposition: failureDispositionInternal,
				reason:      failureReasonInternal,
			},
		},
		{
			name: "deadline exceeded",
			err:  context.DeadlineExceeded,
			want: failureClassification{
				disposition: failureDispositionInternal,
				reason:      failureReasonInternal,
			},
		},
		{
			name: "unknown internal",
			err:  errors.New("unexpected"),
			want: failureClassification{
				disposition: failureDispositionInternal,
				reason:      failureReasonInternal,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyError(tc.err)

			if got != tc.want {
				t.Fatalf(
					"unexpected classification: got %+v, want %+v",
					got,
					tc.want,
				)
			}
		})
	}
}
