package metrics

// FailureReason is a bounded classification of authentication failure
// causes suitable for use as a metric label.
//
// Failure reasons describe authentication semantics rather than raw errors.
// They must be selected explicitly by the authentication boundary and must
// never be derived from error messages or other unbounded input.
type FailureReason string

const (
	// ReasonMissingCredential means no authentication credential was
	// supplied.
	ReasonMissingCredential FailureReason = "missing_credential"

	// ReasonMalformedCredential means a supplied credential was
	// structurally malformed before token processing.
	ReasonMalformedCredential FailureReason = "malformed_credential"

	// ReasonMalformedToken means the supplied token could not be parsed
	// into a structurally valid token representation.
	ReasonMalformedToken FailureReason = "malformed_token"

	// ReasonUnsupportedAlgorithm means the token uses a cryptographic
	// algorithm that is not permitted by the configured policy.
	ReasonUnsupportedAlgorithm FailureReason = "unsupported_algorithm"

	// ReasonInvalidSignature means cryptographic signature verification
	// failed.
	ReasonInvalidSignature FailureReason = "invalid_signature"

	// ReasonExpired means the token is no longer valid because its
	// expiration time has passed.
	ReasonExpired FailureReason = "expired"

	// ReasonNotActive means the token is not yet valid according to its
	// activation time.
	ReasonNotActive FailureReason = "not_active"

	// ReasonInvalidIssuer means the token issuer does not satisfy the
	// configured issuer policy.
	ReasonInvalidIssuer FailureReason = "invalid_issuer"

	// ReasonInvalidAudience means the token audience does not satisfy the
	// configured audience policy.
	ReasonInvalidAudience FailureReason = "invalid_audience"

	// ReasonInvalidClaims means one or more required claims are missing,
	// invalid, or cannot be represented as expected.
	ReasonInvalidClaims FailureReason = "invalid_claims"

	// ReasonInternal means authentication failed because of an unexpected
	// internal error rather than invalid client-supplied authentication
	// data.
	ReasonInternal FailureReason = "internal_error"
)
