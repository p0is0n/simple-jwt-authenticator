package jwt

import (
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"simple-jwt-authenticator/internal/token/claim"
)

// claims is the golang-jwt-specific claims representation. It embeds the
// registered claims and adds the optional human-friendly fields. It never
// escapes this package: callers receive normalized claim.Claims.
type claims struct {
	jwtlib.RegisteredClaims
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
}

// toToken maps the golang-jwt claims into normalized claim.Claims.
func (c claims) toToken() claim.Claims {
	return claim.Claims{
		Subject:   c.Subject,
		Issuer:    c.Issuer,
		Audience:  []string(c.Audience),
		ExpiresAt: numericDate(c.ExpiresAt),
		IssuedAt:  numericDate(c.IssuedAt),
		NotBefore: numericDate(c.NotBefore),
		ID:        c.ID,
		Username:  c.Username,
		Email:     c.Email,
	}
}

// numericDate converts a golang-jwt NumericDate pointer into a standard
// library time.Time pointer, preserving absence as nil.
func numericDate(date *jwtlib.NumericDate) *time.Time {
	if date == nil {
		return nil
	}

	t := date.Time

	return &t
}
