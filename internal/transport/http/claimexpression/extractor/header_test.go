package extractor

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"simple-jwt-authenticator/internal/transport/http/claimexpression"
)

func TestHeader_AbsentIsNotApplicable(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	result, err := (Header{}).Extract(request)
	if err != nil {
		t.Fatalf("Extract() error = %v, want nil", err)
	}

	if result.Extracted {
		t.Fatal("Extracted = true, want false")
	}

	if !result.NotApplicable {
		t.Fatal("NotApplicable = false, want true")
	}

	if result.Source != claimexpression.SourceHeader {
		t.Fatalf(
			"Source = %q, want %q",
			result.Source,
			claimexpression.SourceHeader,
		)
	}
}

func TestHeader_ExtractsExpression(t *testing.T) {
	value := `subject == "camera-front"`

	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	request.Header.Set(
		HeaderName,
		value,
	)

	result, err := (Header{}).Extract(request)
	if err != nil {
		t.Fatalf("Extract() error = %v, want nil", err)
	}

	if !result.Extracted {
		t.Fatal("Extracted = false, want true")
	}

	if result.Value != value {
		t.Fatalf(
			"Value = %q, want %q",
			result.Value,
			value,
		)
	}
}

func TestHeader_RejectsDuplicateValues(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	request.Header.Add(
		HeaderName,
		`subject == "camera-front"`,
	)

	request.Header.Add(
		HeaderName,
		`subject == "camera-back"`,
	)

	_, err := (Header{}).Extract(request)

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

func TestHeader_RejectsEmptyValue(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	request.Header.Set(
		HeaderName,
		"",
	)

	_, err := (Header{}).Extract(request)

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

func TestHeader_RejectsWhitespaceOnlyValue(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/nginx",
		nil,
	)

	request.Header.Set(
		HeaderName,
		"   ",
	)

	_, err := (Header{}).Extract(request)

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
