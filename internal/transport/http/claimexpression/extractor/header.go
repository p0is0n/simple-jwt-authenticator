package extractor

import (
	"fmt"
	"strings"

	stdhttp "net/http"

	"simple-jwt-authenticator/internal/transport/http/claimexpression"
)

// HeaderName is the HTTP header containing an additional claim policy.
const HeaderName = "X-Auth-Claim-Expression"

// Header extracts a claim expression from HeaderName.
type Header struct{}

// Extract implements claimexpression.Extractor.
//
// Duplicate header field values are rejected. Dynamic authorization policy
// must never depend on implicit header merging semantics.
func (Header) Extract(
	request *stdhttp.Request,
) (claimexpression.Extraction, error) {
	values := request.Header.Values(
		HeaderName,
	)

	if len(values) == 0 {
		result := headerResult()
		result.NotApplicable = true

		return result, nil
	}

	if len(values) != 1 {
		return headerResult(),
			fmt.Errorf(
				"%w: %s must be specified exactly once",
				claimexpression.ErrMalformedExpression,
				HeaderName,
			)
	}

	value := values[0]

	if strings.TrimSpace(value) == "" {
		return headerResult(),
			fmt.Errorf(
				"%w: %s must not be empty",
				claimexpression.ErrMalformedExpression,
				HeaderName,
			)
	}

	result := headerResult()
	result.Value = value
	result.Extracted = true

	return result, nil
}

func headerResult() claimexpression.Extraction {
	return claimexpression.Extraction{
		Source: claimexpression.SourceHeader,
	}
}
