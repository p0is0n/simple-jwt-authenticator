package token

import "context"

// Parser parses and verifies a credential value into a normalized token
// representation.
type Parser interface {
	Parse(
		ctx context.Context,
		request ParseRequest,
	) (Token, error)
}
