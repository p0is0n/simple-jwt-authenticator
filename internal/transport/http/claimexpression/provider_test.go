package claimexpression

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"simple-jwt-authenticator/internal/token/claim"
)

type stubExtractor struct {
	extraction Extraction
	err        error
	calls      int
}

func (s *stubExtractor) Extract(
	_ *http.Request,
) (Extraction, error) {
	s.calls++

	return s.extraction, s.err
}

func TestNewProvider_RejectsNoExtractors(t *testing.T) {
	provider, err := NewProvider()

	if !errors.Is(err, ErrNoExtractors) {
		t.Fatalf(
			"error = %v, want ErrNoExtractors",
			err,
		)
	}

	if provider != nil {
		t.Fatalf(
			"provider = %+v, want nil",
			provider,
		)
	}
}

func TestProvider_NoExpressionReturnsNotExtracted(
	t *testing.T,
) {
	provider, err := NewProvider(
		&stubExtractor{
			extraction: Extraction{
				Source:        SourceQuery,
				NotApplicable: true,
			},
		},
		&stubExtractor{
			extraction: Extraction{
				Source:        SourceHeader,
				NotApplicable: true,
			},
		},
	)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := provider.Extract(
		httptest.NewRequest(
			http.MethodGet,
			"/",
			nil,
		),
	)
	if err != nil {
		t.Fatalf("Extract() error = %v, want nil", err)
	}

	if result.Extracted {
		t.Fatal("Extracted = true, want false")
	}

	if result.Expression != nil {
		t.Fatal("Expression != nil, want nil")
	}

	if result.Source != SourceUnknown {
		t.Fatalf(
			"Source = %q, want %q",
			result.Source,
			SourceUnknown,
		)
	}
}

func TestProvider_ParsesSingleExpression(
	t *testing.T,
) {
	provider, err := NewProvider(
		&stubExtractor{
			extraction: Extraction{
				Value:     `subject == "camera-front"`,
				Source:    SourceQuery,
				Extracted: true,
			},
		},
		&stubExtractor{
			extraction: Extraction{
				Source:        SourceHeader,
				NotApplicable: true,
			},
		},
	)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := provider.Extract(
		httptest.NewRequest(
			http.MethodGet,
			"/",
			nil,
		),
	)
	if err != nil {
		t.Fatalf("Extract() error = %v, want nil", err)
	}

	if !result.Extracted {
		t.Fatal("Extracted = false, want true")
	}

	if result.Source != SourceQuery {
		t.Fatalf(
			"Source = %q, want %q",
			result.Source,
			SourceQuery,
		)
	}

	if !claim.Evaluate(
		result.Expression,
		claim.Claims{
			Subject: "camera-front",
		},
	) {
		t.Fatal(
			"parsed expression rejected matching claims",
		)
	}
}

func TestProvider_RejectsMultipleSources(
	t *testing.T,
) {
	provider, err := NewProvider(
		&stubExtractor{
			extraction: Extraction{
				Value:     `subject == "camera-front"`,
				Source:    SourceQuery,
				Extracted: true,
			},
		},
		&stubExtractor{
			extraction: Extraction{
				Value:     `subject == "camera-front"`,
				Source:    SourceHeader,
				Extracted: true,
			},
		},
	)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	_, err = provider.Extract(
		httptest.NewRequest(
			http.MethodGet,
			"/",
			nil,
		),
	)

	if !errors.Is(
		err,
		ErrMultipleExpressions,
	) {
		t.Fatalf(
			"error = %v, want ErrMultipleExpressions",
			err,
		)
	}
}

func TestProvider_RejectsMalformedDSL(
	t *testing.T,
) {
	provider, err := NewProvider(
		&stubExtractor{
			extraction: Extraction{
				Value:     `subject ==`,
				Source:    SourceQuery,
				Extracted: true,
			},
		},
	)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	_, err = provider.Extract(
		httptest.NewRequest(
			http.MethodGet,
			"/",
			nil,
		),
	)

	if !errors.Is(
		err,
		ErrMalformedExpression,
	) {
		t.Fatalf(
			"error = %v, want ErrMalformedExpression",
			err,
		)
	}
}

func TestProvider_DoesNotStopAfterFirstExpression(
	t *testing.T,
) {
	first := &stubExtractor{
		extraction: Extraction{
			Value:     `subject == "camera-front"`,
			Source:    SourceQuery,
			Extracted: true,
		},
	}

	second := &stubExtractor{
		extraction: Extraction{
			Value:     `audience == "frigate"`,
			Source:    SourceHeader,
			Extracted: true,
		},
	}

	provider, err := NewProvider(
		first,
		second,
	)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	_, err = provider.Extract(
		httptest.NewRequest(
			http.MethodGet,
			"/",
			nil,
		),
	)

	if !errors.Is(
		err,
		ErrMultipleExpressions,
	) {
		t.Fatalf(
			"error = %v, want ErrMultipleExpressions",
			err,
		)
	}

	if first.calls != 1 {
		t.Fatalf(
			"first calls = %d, want 1",
			first.calls,
		)
	}

	if second.calls != 1 {
		t.Fatalf(
			"second calls = %d, want 1",
			second.calls,
		)
	}
}

func TestProvider_RejectsInvalidExtractorState(
	t *testing.T,
) {
	provider, err := NewProvider(
		&stubExtractor{
			extraction: Extraction{
				Value:         `subject == "camera-front"`,
				Source:        SourceQuery,
				Extracted:     true,
				NotApplicable: true,
			},
		},
	)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	_, err = provider.Extract(
		httptest.NewRequest(
			http.MethodGet,
			"/",
			nil,
		),
	)

	if !errors.Is(
		err,
		ErrInvalidExtractorResult,
	) {
		t.Fatalf(
			"error = %v, want ErrInvalidExtractorResult",
			err,
		)
	}
}
