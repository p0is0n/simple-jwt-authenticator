package jwt

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"

	"simple-jwt-authenticator/internal/jwt/key"
	"simple-jwt-authenticator/internal/token"
)

type failingVerificationProvider struct {
	err error
}

func (p failingVerificationProvider) Provide(
	_ context.Context,
	_ key.VerificationRequest,
) (crypto.PublicKey, error) {
	return nil, p.err
}

// newTestParser builds a parser bound to a verification provider from the
// given public key, configured for RS256.
func newTestParser(
	t *testing.T,
	publicKeyPEM []byte,
) *Parser {
	t.Helper()

	parsed, err := key.ParsePublic(publicKeyPEM)
	if err != nil {
		t.Fatalf("ParsePublic() error = %v, want nil", err)
	}

	provider := key.NewStaticVerificationProvider(parsed)

	parser, err := NewParser(provider, AlgorithmRS256)
	if err != nil {
		t.Fatalf("NewParser() error = %v, want nil", err)
	}

	return parser
}

func TestParser_ValidRS256Token(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	parsed, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				signValidToken(
					t,
					privateKey,
					"camera-front",
				),
			),
		},
	)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	if got := parsed.Claims.Subject; got != "camera-front" {
		t.Fatalf(
			"subject = %q, want %q",
			got,
			"camera-front",
		)
	}
}

func TestParser_NormalizedClaimMapping(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	parsed, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				signValidToken(
					t,
					privateKey,
					"camera-front",
				),
			),
		},
	)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	claims := parsed.Claims

	if claims.Username != "front" {
		t.Fatalf(
			"username = %q, want %q",
			claims.Username,
			"front",
		)
	}

	if claims.Email != "front@example.com" {
		t.Fatalf(
			"email = %q, want %q",
			claims.Email,
			"front@example.com",
		)
	}

	if claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt = nil, want non-nil")
	}

	if claims.IssuedAt == nil {
		t.Fatal("IssuedAt = nil, want non-nil")
	}

	if claims.NotBefore == nil {
		t.Fatal("NotBefore = nil, want non-nil")
	}
}

func TestParser_InvalidSignature(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	_, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				signWithDifferentKey(
					t,
					"camera-front",
				),
			),
		},
	)

	if !errors.Is(err, token.ErrInvalidSignature) {
		t.Fatalf(
			"Parse() error = %v, want token.ErrInvalidSignature",
			err,
		)
	}
}

func TestParser_MalformedToken(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	_, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: "not.a.jwt",
		},
	)

	if !errors.Is(err, token.ErrMalformedToken) {
		t.Fatalf(
			"Parse() error = %v, want token.ErrMalformedToken",
			err,
		)
	}
}

func TestParser_RejectsNoneAlgorithm(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	_, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				signNoneToken(
					t,
					"camera-front",
				),
			),
		},
	)

	if !errors.Is(err, token.ErrUnsupportedAlgorithm) {
		t.Fatalf(
			"Parse() error = %v, want token.ErrUnsupportedAlgorithm",
			err,
		)
	}
}

func TestParser_RejectsHS256Algorithm(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	_, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				signHS256Token(
					t,
					[]byte("shared-secret"),
					"camera-front",
				),
			),
		},
	)

	if !errors.Is(err, token.ErrUnsupportedAlgorithm) {
		t.Fatalf(
			"Parse() error = %v, want token.ErrUnsupportedAlgorithm",
			err,
		)
	}
}

func TestParser_RejectsWrongRSAAlgorithm(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	_, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				signWrongRSAAlgorithm(
					t,
					privateKey,
					"camera-front",
				),
			),
		},
	)

	if !errors.Is(err, token.ErrUnsupportedAlgorithm) {
		t.Fatalf(
			"Parse() error = %v, want token.ErrUnsupportedAlgorithm",
			err,
		)
	}
}

func TestParser_OptionalClaims(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	parsed, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				optionalClaimsToken(
					t,
					privateKey,
					"camera-front",
				),
			),
		},
	)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	if parsed.Claims.Subject != "camera-front" {
		t.Fatalf(
			"subject = %q, want %q",
			parsed.Claims.Subject,
			"camera-front",
		)
	}

	if parsed.Claims.Username != "" {
		t.Fatalf(
			"username = %q, want empty",
			parsed.Claims.Username,
		)
	}

	if parsed.Claims.Email != "" {
		t.Fatalf(
			"email = %q, want empty",
			parsed.Claims.Email,
		)
	}

	if parsed.Claims.NotBefore != nil {
		t.Fatal("NotBefore != nil, want nil")
	}

	if parsed.Claims.IssuedAt != nil {
		t.Fatal("IssuedAt != nil, want nil")
	}

	if parsed.Claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt = nil, want non-nil")
	}
}

func TestParser_EmptyTokenRejected(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	_, err := parser.Parse(
		context.Background(),
		token.ParseRequest{},
	)

	if !errors.Is(err, token.ErrMalformedToken) {
		t.Fatalf(
			"Parse() error = %v, want token.ErrMalformedToken",
			err,
		)
	}
}

func TestParser_OversizedTokenRejected(t *testing.T) {
	privateKey := testKeys(t)
	parser := newTestParser(t, publicKeyPKIXPEM(t, privateKey))

	_, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				strings.Repeat(
					"a",
					maxTokenLength+1,
				),
			),
		},
	)

	if !errors.Is(err, token.ErrMalformedToken) {
		t.Fatalf(
			"Parse() error = %v, want token.ErrMalformedToken",
			err,
		)
	}
}

func TestParser_VerificationProviderFailurePreserved(t *testing.T) {
	privateKey := testKeys(t)

	providerErr := errors.New("verification provider unavailable")

	parser, err := NewParser(
		failingVerificationProvider{
			err: providerErr,
		},
		AlgorithmRS256,
	)
	if err != nil {
		t.Fatalf("NewParser() error = %v, want nil", err)
	}

	_, err = parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: token.Value(
				signValidToken(
					t,
					privateKey,
					"camera-front",
				),
			),
		},
	)

	if !errors.Is(err, providerErr) {
		t.Fatalf(
			"Parse() error = %v, want provider error preserved",
			err,
		)
	}

	if errors.Is(err, token.ErrUnsupportedAlgorithm) {
		t.Fatalf(
			"Parse() error = %v, verification provider failure must not be classified as unsupported algorithm",
			err,
		)
	}
}

func TestNewParser_NilVerificationProviderRejected(t *testing.T) {
	_, err := NewParser(
		nil,
		AlgorithmRS256,
	)

	if !errors.Is(err, errNilVerificationProvider) {
		t.Fatalf(
			"NewParser() error = %v, want errNilVerificationProvider",
			err,
		)
	}
}

func TestNewParser_UnsupportedTypedAlgorithmRejected(t *testing.T) {
	privateKey := testKeys(t)

	parsedKey, err := key.ParsePublic(
		publicKeyPKIXPEM(
			t,
			privateKey,
		),
	)
	if err != nil {
		t.Fatalf("ParsePublic() error = %v, want nil", err)
	}

	provider := key.NewStaticVerificationProvider(parsedKey)

	_, err = NewParser(
		provider,
		Algorithm("RS512"),
	)

	if !errors.Is(err, token.ErrUnsupportedAlgorithm) {
		t.Fatalf(
			"NewParser() error = %v, want token.ErrUnsupportedAlgorithm",
			err,
		)
	}
}
