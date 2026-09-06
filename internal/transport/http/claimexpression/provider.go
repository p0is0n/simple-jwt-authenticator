package claimexpression

import (
	"fmt"

	stdhttp "net/http"

	claimparser "simple-jwt-authenticator/internal/token/claim/parser"
)

// Provider extracts and parses at most one dynamic claim expression from an
// HTTP request.
//
// Unlike credential extraction, claim-expression sources have no precedence.
// Supplying the expression through more than one configured source is rejected
// rather than resolved by ordering.
//
// This prevents an attacker-controlled source from silently shadowing a policy
// supplied by a trusted reverse proxy.
type Provider struct {
	extractors []Extractor
}

// NewProvider constructs a Provider from the configured HTTP sources.
//
// At least one extractor is required.
func NewProvider(
	extractors ...Extractor,
) (*Provider, error) {
	if len(extractors) == 0 {
		return nil, fmt.Errorf(
			"create claim expression provider: %w",
			ErrNoExtractors,
		)
	}

	return &Provider{
		extractors: extractors,
	}, nil
}

// Extract extracts and parses the request claim expression.
//
// No configured source present:
//
//	Extracted=false, nil error
//
// Exactly one source present:
//
//	parsed claim.Expression
//
// More than one source present:
//
//	ErrMultipleExpressions
//
// A malformed source or expression is a terminal error.
func (p *Provider) Extract(
	request *stdhttp.Request,
) (Result, error) {
	var selected Extraction

	for _, extractor := range p.extractors {
		extraction, err := extractor.Extract(
			request,
		)
		if err != nil {
			return Result{
				Source: extraction.Source,
			}, err
		}

		if err := validateExtraction(
			extraction,
		); err != nil {
			return Result{
				Source: extraction.Source,
			}, err
		}

		if extraction.NotApplicable {
			continue
		}

		if selected.Extracted {
			return Result{}, fmt.Errorf(
				"%w: %s and %s",
				ErrMultipleExpressions,
				selected.Source,
				extraction.Source,
			)
		}

		selected = extraction
	}

	if !selected.Extracted {
		return Result{
			Source: SourceUnknown,
		}, nil
	}

	expression, err := claimparser.Parse(
		selected.Value,
	)
	if err != nil {
		return Result{
				Source: selected.Source,
			},
			fmt.Errorf(
				"%w: %w",
				ErrMalformedExpression,
				err,
			)
	}

	return Result{
		Expression: expression,
		Source:     selected.Source,
		Extracted:  true,
	}, nil
}

// validateExtraction verifies the extractor state machine.
//
// Invalid extractor states represent internal programming errors and must fail
// closed rather than being interpreted as absence.
func validateExtraction(
	extraction Extraction,
) error {
	switch {
	case extraction.Extracted &&
		extraction.NotApplicable:
		return ErrInvalidExtractorResult

	case extraction.Extracted:
		if extraction.Source == SourceUnknown ||
			extraction.Source == "" ||
			extraction.Value == "" {
			return ErrInvalidExtractorResult
		}

		return nil

	case extraction.NotApplicable:
		if extraction.Source == SourceUnknown ||
			extraction.Source == "" {
			return ErrInvalidExtractorResult
		}

		return nil

	default:
		return ErrInvalidExtractorResult
	}
}
