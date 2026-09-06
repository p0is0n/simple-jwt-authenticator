package credential

import (
	"fmt"

	stdhttp "net/http"
)

// Provider runs configured credential extractors in order.
//
// Extractor order is security-sensitive. A terminal extraction error stops
// processing immediately and must not fall back to lower-priority
// credential sources.
//
// Extractor precedence is represented by an ordered slice and must never be
// implemented using an unordered collection.
type Provider struct {
	extractors []Extractor
}

// NewProvider constructs a Provider from an explicitly ordered extractor
// list.
//
// At least one extractor is required.
func NewProvider(extractors ...Extractor) (*Provider, error) {
	if len(extractors) == 0 {
		return nil, fmt.Errorf(
			"create credential provider: %w",
			ErrNoExtractors,
		)
	}

	return &Provider{
		extractors: extractors,
	}, nil
}

// Extract runs extractors in order and returns the first extracted
// credential.
//
// A terminal extraction error stops the chain immediately. Fallback is
// allowed only when the current extractor reports itself as not applicable.
func (p *Provider) Extract(
	request *stdhttp.Request,
) (Result, error) {
	var lastNotApplicable Result

	for _, extractor := range p.extractors {
		result, err := extractor.Extract(request)
		if err != nil {
			return result, err
		}

		if result.Extracted {
			return result, nil
		}

		if result.NotApplicable {
			lastNotApplicable = result
		}
	}

	if lastNotApplicable.NotApplicable {
		return lastNotApplicable, ErrMissingCredential
	}

	return Result{
		Source:        SourceUnknown,
		NotApplicable: true,
	}, ErrMissingCredential
}
