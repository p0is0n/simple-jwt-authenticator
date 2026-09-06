package jwt

import (
	"context"
	"errors"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"simple-jwt-authenticator/internal/jwt/key"
	"simple-jwt-authenticator/internal/token"
)

func newTestGenerator(
	t *testing.T,
	privateKeyPEMBytes []byte,
) *Generator {
	t.Helper()

	privateKey, err := key.ParsePrivate(privateKeyPEMBytes)
	if err != nil {
		t.Fatalf("ParsePrivate() error = %v, want nil", err)
	}

	provider := key.NewStaticSigningProvider(privateKey)

	generator, err := NewGenerator(
		provider,
		AlgorithmRS256,
		"home-auth",
		time.Hour,
		168*time.Hour,
	)
	if err != nil {
		t.Fatalf("NewGenerator() error = %v, want nil", err)
	}

	return generator
}

func TestGenerator_DefaultTTL(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	signed, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject:  "camera-front",
			Audience: []string{"internal-services"},
		},
	)
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}

	parsed := parseGenerated(t, signed)

	if parsed.Claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt = nil, want non-nil")
	}
}

func TestGenerator_ExplicitTTL(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	ttl := 30 * time.Minute

	signed, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject:  "camera-front",
			Audience: []string{"internal-services"},
			TTL:      &ttl,
		},
	)
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}

	parsed := parseGenerated(t, signed)

	if parsed.Claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt = nil, want non-nil")
	}

	if parsed.Claims.IssuedAt == nil {
		t.Fatal("IssuedAt = nil, want non-nil")
	}

	got := parsed.Claims.ExpiresAt.Sub(
		*parsed.Claims.IssuedAt,
	)

	if got < 29*time.Minute || got > 31*time.Minute {
		t.Fatalf(
			"token TTL = %s, want approximately %s",
			got,
			ttl,
		)
	}
}

func TestGenerator_ExplicitZeroTTLRejected(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	ttl := time.Duration(0)

	_, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject:  "camera-front",
			Audience: []string{"internal-services"},
			TTL:      &ttl,
		},
	)

	if !errors.Is(err, errInvalidTTL) {
		t.Fatalf(
			"Generate() error = %v, want errInvalidTTL",
			err,
		)
	}
}

func TestGenerator_NegativeTTLRejected(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	ttl := -time.Second

	_, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject:  "camera-front",
			Audience: []string{"internal-services"},
			TTL:      &ttl,
		},
	)

	if !errors.Is(err, errInvalidTTL) {
		t.Fatalf(
			"Generate() error = %v, want errInvalidTTL",
			err,
		)
	}
}

func TestGenerator_TTLAboveMaximumRejected(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	ttl := 200 * time.Hour

	_, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject:  "camera-front",
			Audience: []string{"internal-services"},
			TTL:      &ttl,
		},
	)

	if !errors.Is(err, errInvalidTTL) {
		t.Fatalf(
			"Generate() error = %v, want errInvalidTTL",
			err,
		)
	}
}

func TestGenerator_GeneratedClaims(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	signed, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject:  "camera-front",
			Username: "front",
			Email:    "front@example.com",
			Audience: []string{"internal-services"},
		},
	)
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}

	parsed := parseGenerated(t, signed)

	if parsed.Claims.Subject != "camera-front" {
		t.Fatalf(
			"subject = %q, want %q",
			parsed.Claims.Subject,
			"camera-front",
		)
	}

	if parsed.Claims.Issuer != "home-auth" {
		t.Fatalf(
			"issuer = %q, want %q",
			parsed.Claims.Issuer,
			"home-auth",
		)
	}

	if len(parsed.Claims.Audience) != 1 ||
		parsed.Claims.Audience[0] != "internal-services" {
		t.Fatalf(
			"audience = %v, want [internal-services]",
			parsed.Claims.Audience,
		)
	}

	if parsed.Claims.Username != "front" {
		t.Fatalf(
			"username = %q, want %q",
			parsed.Claims.Username,
			"front",
		)
	}

	if parsed.Claims.Email != "front@example.com" {
		t.Fatalf(
			"email = %q, want %q",
			parsed.Claims.Email,
			"front@example.com",
		)
	}

	if parsed.Claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt = nil, want non-nil")
	}

	if parsed.Claims.IssuedAt == nil {
		t.Fatal("IssuedAt = nil, want non-nil")
	}

	if parsed.Claims.NotBefore == nil {
		t.Fatal("NotBefore = nil, want non-nil")
	}

	if parsed.Claims.ID == "" {
		t.Fatal("ID = empty, want generated JTI")
	}
}

func TestGenerator_JTIIsUnique(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	first, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject: "camera-front",
		},
	)
	if err != nil {
		t.Fatalf("first Generate() error = %v, want nil", err)
	}

	second, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject: "camera-front",
		},
	)
	if err != nil {
		t.Fatalf("second Generate() error = %v, want nil", err)
	}

	firstParsed := parseGenerated(t, first)
	secondParsed := parseGenerated(t, second)

	if firstParsed.Claims.ID == secondParsed.Claims.ID {
		t.Fatalf(
			"JTI values are equal: %q",
			firstParsed.Claims.ID,
		)
	}
}

func TestGenerator_EmptySubjectRejected(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	_, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{},
	)

	if !errors.Is(err, errEmptySubject) {
		t.Fatalf(
			"Generate() error = %v, want errEmptySubject",
			err,
		)
	}
}

func TestGenerator_WhitespaceSubjectRejected(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	_, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject: "   ",
		},
	)

	if !errors.Is(err, errEmptySubject) {
		t.Fatalf(
			"Generate() error = %v, want errEmptySubject",
			err,
		)
	}
}

func TestGenerator_GeneratedTokenValidatesWithParser(t *testing.T) {
	privateKey := testKeys(t)
	generator := newTestGenerator(
		t,
		privateKeyPKCS1PEMBytes(t, privateKey),
	)

	signed, err := generator.Generate(
		context.Background(),
		token.GenerateRequest{
			Subject:  "camera-front",
			Username: "front",
			Email:    "front@example.com",
			Audience: []string{"internal-services"},
		},
	)
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}

	parser := newTestParser(
		t,
		publicKeyPKIXPEM(t, privateKey),
	)

	parsed, err := parser.Parse(
		context.Background(),
		token.ParseRequest{
			Value: signed.Value,
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
}

func TestNewGenerator_NilSigningProviderRejected(t *testing.T) {
	_, err := NewGenerator(
		nil,
		AlgorithmRS256,
		"home-auth",
		time.Hour,
		168*time.Hour,
	)

	if !errors.Is(err, errNilSigningProvider) {
		t.Fatalf(
			"NewGenerator() error = %v, want errNilSigningProvider",
			err,
		)
	}
}

func TestNewGenerator_UnsupportedTypedAlgorithmRejected(t *testing.T) {
	privateKey := testKeys(t)

	provider := key.NewStaticSigningProvider(
		privateKey,
	)

	_, err := NewGenerator(
		provider,
		Algorithm("RS512"),
		"home-auth",
		time.Hour,
		168*time.Hour,
	)

	if !errors.Is(err, token.ErrUnsupportedAlgorithm) {
		t.Fatalf(
			"NewGenerator() error = %v, want token.ErrUnsupportedAlgorithm",
			err,
		)
	}
}

func TestNewGenerator_InvalidTTLPolicyRejected(t *testing.T) {
	privateKey := testKeys(t)

	provider := key.NewStaticSigningProvider(
		privateKey,
	)

	tests := []struct {
		name       string
		defaultTTL time.Duration
		maxTTL     time.Duration
		wantErr    error
	}{
		{
			name:       "zero default ttl",
			defaultTTL: 0,
			maxTTL:     time.Hour,
			wantErr:    errInvalidDefaultTTL,
		},
		{
			name:       "negative default ttl",
			defaultTTL: -time.Second,
			maxTTL:     time.Hour,
			wantErr:    errInvalidDefaultTTL,
		},
		{
			name:       "zero maximum ttl",
			defaultTTL: time.Minute,
			maxTTL:     0,
			wantErr:    errInvalidMaxTTL,
		},
		{
			name:       "negative maximum ttl",
			defaultTTL: time.Minute,
			maxTTL:     -time.Second,
			wantErr:    errInvalidMaxTTL,
		},
		{
			name:       "default exceeds maximum",
			defaultTTL: 2 * time.Hour,
			maxTTL:     time.Hour,
			wantErr:    errInvalidDefaultTTL,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewGenerator(
				provider,
				AlgorithmRS256,
				"home-auth",
				test.defaultTTL,
				test.maxTTL,
			)

			if !errors.Is(err, test.wantErr) {
				t.Fatalf(
					"NewGenerator() error = %v, want %v",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func parseGenerated(
	t *testing.T,
	signed token.SerializedToken,
) token.Token {
	t.Helper()

	parser := jwtlib.NewParser(
		jwtlib.WithoutClaimsValidation(),
	)

	parsedClaims := claims{}

	if _, _, err := parser.ParseUnverified(
		string(signed.Value),
		&parsedClaims,
	); err != nil {
		t.Fatalf(
			"ParseUnverified() error = %v, want nil",
			err,
		)
	}

	return token.Token{
		Claims: parsedClaims.toToken(),
	}
}
