package validator

import (
	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

// Request contains the normalized token and additional policy required for
// validation.
//
// ClaimExpression is optional and supplements the configured validation
// policy. It must never replace or weaken configured validation rules.
type Request struct {
	Token           token.Token
	ClaimExpression claim.Expression
}
