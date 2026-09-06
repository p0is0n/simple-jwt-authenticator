package extractor

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"simple-jwt-authenticator/internal/transport/http/claimexpression"
)

func TestQuery_AbsentIsNotApplicable(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	result, err := (Query{}).Extract(request)
	if err != nil {
		t.Fatalf("Extract() error = %v, want nil", err)
	}

	if result.Extracted {
		t.Fatal("Extracted = true, want false")
	}

	if !result.NotApplicable {
		t.Fatal("NotApplicable = false, want true")
	}

	if result.Source != claimexpression.SourceQuery {
		t.Fatalf(
			"Source = %q, want %q",
			result.Source,
			claimexpression.SourceQuery,
		)
	}
}

func TestQuery_ExtractsExpression(t *testing.T) {
	value := `subject == "camera-front"`

	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx?"+url.Values{
			QueryParameter: []string{
				value,
			},
		}.Encode(),
		nil,
	)

	result, err := (Query{}).Extract(request)
	if err != nil {
		t.Fatalf("Extract() error = %v, want nil", err)
	}

	if !result.Extracted {
		t.Fatal("Extracted = false, want true")
	}

	if result.NotApplicable {
		t.Fatal("NotApplicable = true, want false")
	}

	if result.Value != value {
		t.Fatalf(
			"Value = %q, want %q",
			result.Value,
			value,
		)
	}
}

func TestQuery_RejectsDuplicateValues(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx?claim-expression=a&claim-expression=b",
		nil,
	)

	_, err := (Query{}).Extract(request)

	if !errors.Is(
		err,
		claimexpression.ErrMalformedExpression,
	) {
		t.Fatalf(
			"error = %v, want ErrMalformedExpression",
			err,
		)
	}
}

func TestQuery_RejectsEmptyValue(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx?claim-expression=",
		nil,
	)

	_, err := (Query{}).Extract(request)

	if !errors.Is(
		err,
		claimexpression.ErrMalformedExpression,
	) {
		t.Fatalf(
			"error = %v, want ErrMalformedExpression",
			err,
		)
	}
}

func TestQuery_RejectsWhitespaceOnlyValue(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx?"+url.Values{
			QueryParameter: []string{
				"   ",
			},
		}.Encode(),
		nil,
	)

	_, err := (Query{}).Extract(request)

	if !errors.Is(
		err,
		claimexpression.ErrMalformedExpression,
	) {
		t.Fatalf(
			"error = %v, want ErrMalformedExpression",
			err,
		)
	}
}

func TestQuery_RejectsMalformedURLQuery(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	request.URL.RawQuery = "claim-expression=%ZZ"

	_, err := (Query{}).Extract(request)

	if !errors.Is(
		err,
		claimexpression.ErrMalformedExpression,
	) {
		t.Fatalf(
			"error = %v, want ErrMalformedExpression",
			err,
		)
	}
}
