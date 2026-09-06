package validator

import (
	"context"
	"errors"
	"testing"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

func TestAudience_MatchingAudienceAccepted(t *testing.T) {
	audience := Audience{
		Expected: []string{
			"internal-services",
			"cameras",
		},
	}

	err := audience.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Audience: []string{
						"other",
						"cameras",
					},
				},
			},
		},
	)

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestAudience_NoMatchingAudienceRejected(t *testing.T) {
	audience := Audience{
		Expected: []string{
			"internal-services",
			"cameras",
		},
	}

	err := audience.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Audience: []string{
						"other",
						"dashboard",
					},
				},
			},
		},
	)

	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf(
			"expected ErrInvalidAudience, got %v",
			err,
		)
	}
}

func TestAudience_MissingTokenAudienceRejectedWhenExpected(t *testing.T) {
	audience := Audience{
		Expected: []string{
			"internal-services",
		},
	}

	err := audience.Validate(
		context.Background(),
		Request{
			Token: token.Token{},
		},
	)

	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf(
			"expected ErrInvalidAudience, got %v",
			err,
		)
	}
}

func TestAudience_EmptyExpectedAcceptsAnyAudience(t *testing.T) {
	audience := Audience{}

	err := audience.Validate(
		context.Background(),
		Request{
			Token: token.Token{
				Claims: claim.Claims{
					Audience: []string{
						"anything",
					},
				},
			},
		},
	)

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestAudience_EmptyExpectedAcceptsMissingAudience(t *testing.T) {
	audience := Audience{}

	err := audience.Validate(
		context.Background(),
		Request{
			Token: token.Token{},
		},
	)

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}
