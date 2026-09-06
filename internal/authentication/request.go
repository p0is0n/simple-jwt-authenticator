package authentication

import "simple-jwt-authenticator/internal/token/claim"

// Request contains the transport-independent input required to authenticate
// a credential.
//
// ClaimExpression is optional policy evaluated in addition to the configured
// token-validation policy.
type Request struct {
	Credential      Credential
	ClaimExpression claim.Expression
}
