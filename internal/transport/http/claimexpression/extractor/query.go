// Package extractor contains concrete HTTP claim-expression extractors.
package extractor

import (
	"fmt"
	"net/url"
	"strings"

	stdhttp "net/http"

	"simple-jwt-authenticator/internal/transport/http/claimexpression"
)

// QueryParameter is the query parameter containing an additional claim policy.
const QueryParameter = "claim-expression"

// Query extracts a claim expression from the configured query parameter.
type Query struct{}

// Extract implements claimexpression.Extractor.
//
// Behavior:
//
//	parameter absent      -> not applicable
//	one non-empty value   -> extracted
//	duplicate parameter   -> terminal malformed error
//	empty value           -> terminal malformed error
//	malformed URL query   -> terminal malformed error
func (Query) Extract(
	request *stdhttp.Request,
) (claimexpression.Extraction, error) {
	query, err := url.ParseQuery(
		request.URL.RawQuery,
	)
	if err != nil {
		return queryResult(),
			fmt.Errorf(
				"%w: parse query: %w",
				claimexpression.ErrMalformedExpression,
				err,
			)
	}

	values, exists := query[QueryParameter]
	if !exists {
		result := queryResult()
		result.NotApplicable = true

		return result, nil
	}

	if len(values) != 1 {
		return queryResult(),
			fmt.Errorf(
				"%w: %s must be specified exactly once",
				claimexpression.ErrMalformedExpression,
				QueryParameter,
			)
	}

	value := values[0]

	if strings.TrimSpace(value) == "" {
		return queryResult(),
			fmt.Errorf(
				"%w: %s must not be empty",
				claimexpression.ErrMalformedExpression,
				QueryParameter,
			)
	}

	result := queryResult()
	result.Value = value
	result.Extracted = true

	return result, nil
}

func queryResult() claimexpression.Extraction {
	return claimexpression.Extraction{
		Source: claimexpression.SourceQuery,
	}
}
