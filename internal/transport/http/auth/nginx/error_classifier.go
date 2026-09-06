package nginx

import (
	"errors"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/validator"
	"simple-jwt-authenticator/internal/transport/http/claimexpression"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

// failureDisposition defines how a classified adapter failure is exposed at
// the HTTP boundary.
type failureDisposition uint8

const (
	failureDispositionInternal failureDisposition = iota
	failureDispositionBadRequest
	failureDispositionUnauthorized
)

// failureReason is the adapter-local, bounded reason for an authentication
// flow failure.
//
// It is intentionally independent of metrics so observability cannot influence
// HTTP or security semantics.
type failureReason uint8

const (
	failureReasonInternal failureReason = iota
	failureReasonMissingCredential
	failureReasonMalformedCredential
	failureReasonMalformedToken
	failureReasonUnsupportedAlgorithm
	failureReasonInvalidSignature
	failureReasonExpired
	failureReasonNotActive
	failureReasonInvalidIssuer
	failureReasonInvalidAudience
	failureReasonInvalidClaims
	failureReasonMalformedClaimExpression
	failureReasonClaimExpressionNotSatisfied
)

// failureClassification contains the security-relevant transport disposition
// and a bounded adapter-local reason.
type failureClassification struct {
	disposition failureDisposition
	reason      failureReason
}

// classifyError classifies known authentication and HTTP policy rejections.
//
// Unknown errors fail closed as internal failures. In particular, broad
// authentication sentinels or claim-expression provider construction failures
// are not sufficient on their own to classify an error as client-controlled.
func classifyError(err error) failureClassification {
	switch {
	case errors.Is(
		err,
		claimexpression.ErrMalformedExpression,
	),
		errors.Is(
			err,
			claimexpression.ErrMultipleExpressions,
		):
		return badRequestFailure(
			failureReasonMalformedClaimExpression,
		)

	case errors.Is(err, credential.ErrMissingCredential),
		errors.Is(err, authentication.ErrMissingCredential):
		return unauthorizedFailure(
			failureReasonMissingCredential,
		)

	case errors.Is(err, credential.ErrMalformedCredential):
		return unauthorizedFailure(
			failureReasonMalformedCredential,
		)

	case errors.Is(err, token.ErrMalformedToken):
		return unauthorizedFailure(
			failureReasonMalformedToken,
		)

	case errors.Is(err, token.ErrUnsupportedAlgorithm):
		return unauthorizedFailure(
			failureReasonUnsupportedAlgorithm,
		)

	case errors.Is(err, token.ErrInvalidSignature):
		return unauthorizedFailure(
			failureReasonInvalidSignature,
		)

	case errors.Is(err, validator.ErrExpired):
		return unauthorizedFailure(
			failureReasonExpired,
		)

	case errors.Is(err, validator.ErrNotActive):
		return unauthorizedFailure(
			failureReasonNotActive,
		)

	case errors.Is(err, validator.ErrInvalidIssuer):
		return unauthorizedFailure(
			failureReasonInvalidIssuer,
		)

	case errors.Is(err, validator.ErrInvalidAudience):
		return unauthorizedFailure(
			failureReasonInvalidAudience,
		)

	case errors.Is(
		err,
		validator.ErrClaimExpressionNotSatisfied,
	):
		return unauthorizedFailure(
			failureReasonClaimExpressionNotSatisfied,
		)

	case errors.Is(err, validator.ErrMissingClaim),
		errors.Is(err, validator.ErrIssuedAtFuture),
		errors.Is(err, authentication.ErrInvalidIdentity):
		return unauthorizedFailure(
			failureReasonInvalidClaims,
		)

	default:
		return failureClassification{
			disposition: failureDispositionInternal,
			reason:      failureReasonInternal,
		}
	}
}

func badRequestFailure(
	reason failureReason,
) failureClassification {
	return failureClassification{
		disposition: failureDispositionBadRequest,
		reason:      reason,
	}
}

func unauthorizedFailure(
	reason failureReason,
) failureClassification {
	return failureClassification{
		disposition: failureDispositionUnauthorized,
		reason:      reason,
	}
}
