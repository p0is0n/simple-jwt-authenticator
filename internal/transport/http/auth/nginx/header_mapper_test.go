package nginx

import (
	"errors"
	"net/http"
	"testing"
)

func TestDefaultHeaderMapper_MapsSafeIdentity(t *testing.T) {
	headers := make(http.Header)

	err := (defaultHeaderMapper{}).Apply(
		headers,
		identity{
			Subject:  "camera-front",
			Username: "front",
			Email:    "front@example.com",
		},
	)
	if err != nil {
		t.Fatalf("apply identity headers: %v", err)
	}

	if got := headers.Get(HeaderSubject); got != "camera-front" {
		t.Fatalf(
			"unexpected subject: got %q, want %q",
			got,
			"camera-front",
		)
	}

	if got := headers.Get(HeaderUsername); got != "front" {
		t.Fatalf(
			"unexpected username: got %q, want %q",
			got,
			"front",
		)
	}

	if got := headers.Get(HeaderEmail); got != "front@example.com" {
		t.Fatalf(
			"unexpected email: got %q, want %q",
			got,
			"front@example.com",
		)
	}
}

func TestDefaultHeaderMapper_OmitsEmptyOptionalFields(t *testing.T) {
	headers := make(http.Header)

	err := (defaultHeaderMapper{}).Apply(
		headers,
		identity{
			Subject: "camera-front",
		},
	)
	if err != nil {
		t.Fatalf("apply identity headers: %v", err)
	}

	if _, exists := headers[HeaderUsername]; exists {
		t.Fatal("username header must be omitted")
	}

	if _, exists := headers[HeaderEmail]; exists {
		t.Fatal("email header must be omitted")
	}
}

func TestDefaultHeaderMapper_RejectsMissingSubject(t *testing.T) {
	headers := make(http.Header)

	err := (defaultHeaderMapper{}).Apply(
		headers,
		identity{
			Username: "front",
		},
	)

	if !errors.Is(err, errMissingIdentitySubject) {
		t.Fatalf(
			"expected errMissingIdentitySubject, got %v",
			err,
		)
	}

	if len(headers) != 0 {
		t.Fatalf(
			"headers mutated after failed validation: %v",
			headers,
		)
	}
}

func TestDefaultHeaderMapper_RejectsControlBytesAtomically(
	t *testing.T,
) {
	cases := []struct {
		name string
		id   identity
	}{
		{
			name: "subject CRLF",
			id: identity{
				Subject: "camera\r\nX-Injected: evil",
			},
		},
		{
			name: "subject NUL",
			id: identity{
				Subject: "camera\x00front",
			},
		},
		{
			name: "username tab",
			id: identity{
				Subject:  "camera-front",
				Username: "front\tadmin",
			},
		},
		{
			name: "email DEL",
			id: identity{
				Subject: "camera-front",
				Email:   "front\x7f@example.com",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)

			err := (defaultHeaderMapper{}).Apply(
				headers,
				tc.id,
			)

			if !errors.Is(err, errUnsafeHeaderValue) {
				t.Fatalf(
					"expected errUnsafeHeaderValue, got %v",
					err,
				)
			}

			if len(headers) != 0 {
				t.Fatalf(
					"headers mutated after failed validation: %v",
					headers,
				)
			}
		})
	}
}
