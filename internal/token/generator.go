package token

import "context"

// Generator generates a token from a normalized generation request.
type Generator interface {
	Generate(
		ctx context.Context,
		request GenerateRequest,
	) (SerializedToken, error)
}
