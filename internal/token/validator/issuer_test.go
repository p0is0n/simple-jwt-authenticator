package validator

import (
	"context"
	"errors"
	"testing"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

func TestIssuer_MatchingIssuerAccepted(t *testing.T) {
	issuer := Issuer{
		Expected: "home-auth",
	}

	err := issuer.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Issuer: "home-auth",
				},
			},
		},
	)

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestIssuer_MismatchingIssuerRejected(t *testing.T) {
	issuer := Issuer{
		Expected: "home-auth",
	}

	err := issuer.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Issuer: "other",
				},
			},
		},
	)

	if !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf(
			"expected ErrInvalidIssuer, got %v",
			err,
		)
	}
}

func TestIssuer_EmptyExpectedAcceptsAnyIssuer(t *testing.T) {
	issuer := Issuer{}

	err := issuer.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Issuer: "any",
				},
			},
		},
	)

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}
