package nginx

import (
	"testing"

	"simple-jwt-authenticator/internal/metrics"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

func TestMetricFailureReasonIsBounded(t *testing.T) {
	cases := []struct {
		name   string
		reason failureReason
		want   metrics.FailureReason
	}{
		{
			name:   "missing credential",
			reason: failureReasonMissingCredential,
			want:   metrics.ReasonMissingCredential,
		},
		{
			name:   "invalid signature",
			reason: failureReasonInvalidSignature,
			want:   metrics.ReasonInvalidSignature,
		},
		{
			name:   "expired",
			reason: failureReasonExpired,
			want:   metrics.ReasonExpired,
		},
		{
			name:   "invalid claims",
			reason: failureReasonInvalidClaims,
			want:   metrics.ReasonInvalidClaims,
		},
		{
			name:   "malformed claim expression",
			reason: failureReasonMalformedClaimExpression,
			want:   metrics.ReasonInvalidClaims,
		},
		{
			name:   "claim expression not satisfied",
			reason: failureReasonClaimExpressionNotSatisfied,
			want:   metrics.ReasonInvalidClaims,
		},
		{
			name:   "internal",
			reason: failureReasonInternal,
			want:   metrics.ReasonInternal,
		},
		{
			name:   "unknown local value",
			reason: failureReason(255),
			want:   metrics.ReasonInternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := metricFailureReason(tc.reason)

			if got != tc.want {
				t.Fatalf(
					"unexpected metric reason: got %q, want %q",
					got,
					tc.want,
				)
			}
		})
	}
}

func TestMetricCredentialSourceIsBounded(t *testing.T) {
	cases := []struct {
		name   string
		source credential.Source
		want   string
	}{
		{
			name:   "authorization header",
			source: credential.SourceAuthorizationHeader,
			want: string(
				credential.SourceAuthorizationHeader,
			),
		},
		{
			name:   "cookie",
			source: credential.SourceCookie,
			want: string(
				credential.SourceCookie,
			),
		},
		{
			name:   "unknown",
			source: credential.SourceUnknown,
			want: string(
				credential.SourceUnknown,
			),
		},
		{
			name:   "empty",
			source: "",
			want: string(
				credential.SourceUnknown,
			),
		},
		{
			name: "unrecognized value",
			source: credential.Source(
				"attacker-controlled-source",
			),
			want: string(
				credential.SourceUnknown,
			),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := metricCredentialSource(tc.source)

			if got != tc.want {
				t.Fatalf(
					"unexpected metric source: got %q, want %q",
					got,
					tc.want,
				)
			}
		})
	}
}
