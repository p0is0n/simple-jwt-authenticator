package token

import "time"

// ParseRequest contains the serialized token value to be parsed.
type ParseRequest struct {
	Value Value
}

// GenerateRequest describes the claims and lifetime requested for a new token.
//
// TTL is a pointer so the generator can distinguish an omitted value from
// an explicitly supplied duration.
type GenerateRequest struct {
	Subject  string
	Username string
	Email    string
	Audience []string
	TTL      *time.Duration
}
