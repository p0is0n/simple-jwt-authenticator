package nginx

import (
	"simple-jwt-authenticator/internal/metrics"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

// metricFailureReason maps the adapter-local bounded failure taxonomy to the
// metrics taxonomy.
//
// Metrics are downstream consumers of adapter decisions and must never drive
// HTTP or authentication behavior.
func metricFailureReason(
	reason failureReason,
) metrics.FailureReason {
	switch reason {
	case failureReasonMissingCredential:
		return metrics.ReasonMissingCredential

	case failureReasonMalformedCredential:
		return metrics.ReasonMalformedCredential

	case failureReasonMalformedToken:
		return metrics.ReasonMalformedToken

	case failureReasonUnsupportedAlgorithm:
		return metrics.ReasonUnsupportedAlgorithm

	case failureReasonInvalidSignature:
		return metrics.ReasonInvalidSignature

	case failureReasonExpired:
		return metrics.ReasonExpired

	case failureReasonNotActive:
		return metrics.ReasonNotActive

	case failureReasonInvalidIssuer:
		return metrics.ReasonInvalidIssuer

	case failureReasonInvalidAudience:
		return metrics.ReasonInvalidAudience

	case failureReasonInvalidClaims,
		failureReasonMalformedClaimExpression,
		failureReasonClaimExpressionNotSatisfied:
		return metrics.ReasonInvalidClaims

	case failureReasonInternal:
		return metrics.ReasonInternal

	default:
		// Unknown local values must never escape into metric labels.
		return metrics.ReasonInternal
	}
}

// metricCredentialSource maps credential sources to a bounded metric label.
//
// Unknown or future source values are deliberately collapsed into "unknown"
// instead of being emitted directly, preventing accidental metric cardinality
// growth.
func metricCredentialSource(
	source credential.Source,
) string {
	switch source {
	case credential.SourceAuthorizationHeader:
		return string(credential.SourceAuthorizationHeader)

	case credential.SourceCookie:
		return string(credential.SourceCookie)

	case credential.SourceUnknown, "":
		return string(credential.SourceUnknown)

	default:
		return string(credential.SourceUnknown)
	}
}
