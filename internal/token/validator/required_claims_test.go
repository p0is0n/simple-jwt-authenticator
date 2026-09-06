package validator

import (
	"context"
	"errors"
	"testing"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

func TestRequiredClaims_MissingSubjectFails(t *testing.T) {
	err := RequiredClaims{}.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{},
			},
		},
	)

	if !errors.Is(err, ErrMissingClaim) {
		t.Fatalf(
			"expected ErrMissingClaim, got %v",
			err,
		)
	}
}

func TestRequiredClaims_SubjectSucceeds(t *testing.T) {
	err := RequiredClaims{}.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Subject: "camera-front",
				},
			},
		},
	)

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestRequiredClaims_UsernameAndEmailAreOptional(t *testing.T) {
	err := RequiredClaims{}.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Subject:  "camera-front",
					Username: "",
					Email:    "",
				},
			},
		},
	)

	if err != nil {
		t.Fatalf(
			"expected optional username and email to be accepted, got %v",
			err,
		)
	}
}
