package jwt

import (
	"errors"
	"testing"

	"simple-jwt-authenticator/internal/token"
)

func TestParseAlgorithm_RS256(t *testing.T) {
	alg, err := ParseAlgorithm("RS256")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if alg != AlgorithmRS256 {
		t.Fatalf(
			"unexpected algorithm: got %s",
			alg,
		)
	}

	if alg.String() != "RS256" {
		t.Fatalf(
			"unexpected string: got %s",
			alg.String(),
		)
	}
}

func TestParseAlgorithm_RejectsUnsupported(t *testing.T) {
	cases := []string{
		"none",
		"HS256",
		"RS512",
		"ES256",
		"",
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := ParseAlgorithm(tc)
			if !errors.Is(err, token.ErrUnsupportedAlgorithm) {
				t.Fatalf(
					"expected token.ErrUnsupportedAlgorithm for %s, got %v",
					tc,
					err,
				)
			}
		})
	}
}
