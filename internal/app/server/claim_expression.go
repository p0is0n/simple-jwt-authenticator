package server

import (
	"fmt"

	"simple-jwt-authenticator/internal/transport/http/claimexpression"
	claimextractor "simple-jwt-authenticator/internal/transport/http/claimexpression/extractor"
)

// newClaimExpressionProvider constructs the HTTP dynamic-claim-policy sources.
//
// Query and header are intentionally peers rather than precedence-ordered
// alternatives. The provider rejects requests containing both sources.
//
// This keeps source ambiguity fail-closed and prevents one HTTP source from
// silently overriding another.
func newClaimExpressionProvider() (
	*claimexpression.Provider,
	error,
) {
	provider, err := claimexpression.NewProvider(
		claimextractor.Query{},
		claimextractor.Header{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"construct claim expression provider: %w",
			err,
		)
	}

	return provider, nil
}
