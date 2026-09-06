package jwt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"simple-jwt-authenticator/internal/jwt/key"
	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

// Generator is the concrete JWT token generator.
type Generator struct {
	signingProvider key.SigningProvider
	algorithm       Algorithm
	issuer          string
	defaultTTL      time.Duration
	maxTTL          time.Duration
	now             func() time.Time
	newID           func() (string, error)
}

// NewGenerator constructs a Generator with a bounded token-lifetime policy.
func NewGenerator(
	signingProvider key.SigningProvider,
	algorithm Algorithm,
	issuer string,
	defaultTTL time.Duration,
	maxTTL time.Duration,
) (*Generator, error) {
	if signingProvider == nil {
		return nil, fmt.Errorf(
			"create jwt generator: %w",
			errNilSigningProvider,
		)
	}

	if err := algorithm.validate(); err != nil {
		return nil, fmt.Errorf(
			"create jwt generator: %w",
			err,
		)
	}

	if defaultTTL <= 0 {
		return nil, fmt.Errorf(
			"create jwt generator: %w: got %s",
			errInvalidDefaultTTL,
			defaultTTL,
		)
	}

	if maxTTL <= 0 {
		return nil, fmt.Errorf(
			"create jwt generator: %w: got %s",
			errInvalidMaxTTL,
			maxTTL,
		)
	}

	if defaultTTL > maxTTL {
		return nil, fmt.Errorf(
			"create jwt generator: %w: %s exceeds maximum %s",
			errInvalidDefaultTTL,
			defaultTTL,
			maxTTL,
		)
	}

	return &Generator{
		signingProvider: signingProvider,
		algorithm:       algorithm,
		issuer:          issuer,
		defaultTTL:      defaultTTL,
		maxTTL:          maxTTL,
		now:             time.Now,
		newID:           newJTI,
	}, nil
}

// Generate implements token.Generator.
func (g *Generator) Generate(
	ctx context.Context,
	request token.GenerateRequest,
) (token.SerializedToken, error) {
	if err := ctx.Err(); err != nil {
		return token.SerializedToken{}, err
	}

	if strings.TrimSpace(request.Subject) == "" {
		return token.SerializedToken{}, errEmptySubject
	}

	ttl, err := g.resolveTTL(request.TTL)
	if err != nil {
		return token.SerializedToken{}, err
	}

	signer, err := g.signingProvider.Provide(
		ctx,
		key.SigningRequest{
			Algorithm: g.algorithm.String(),
		},
	)
	if err != nil {
		return token.SerializedToken{}, fmt.Errorf(
			"obtain signing key: %w",
			err,
		)
	}

	method := g.signingMethod()
	if method == nil {
		return token.SerializedToken{}, fmt.Errorf(
			"%w: %q",
			token.ErrUnsupportedAlgorithm,
			g.algorithm,
		)
	}

	id, err := g.newID()
	if err != nil {
		return token.SerializedToken{}, fmt.Errorf(
			"generate token id: %w",
			err,
		)
	}

	now := g.now()
	expiresAt := now.Add(ttl)

	registered := jwtlib.RegisteredClaims{
		Issuer:    g.issuer,
		Subject:   request.Subject,
		Audience:  jwtlib.ClaimStrings(request.Audience),
		ExpiresAt: jwtlib.NewNumericDate(expiresAt),
		NotBefore: jwtlib.NewNumericDate(now),
		IssuedAt:  jwtlib.NewNumericDate(now),
		ID:        id,
	}

	generatedClaims := claims{
		RegisteredClaims: registered,
		Username:         request.Username,
		Email:            request.Email,
	}

	jwtToken := jwtlib.NewWithClaims(
		method,
		generatedClaims,
	)

	signed, err := jwtToken.SignedString(signer)
	if err != nil {
		return token.SerializedToken{}, fmt.Errorf(
			"sign token: %w",
			err,
		)
	}

	return token.SerializedToken{
		Value: token.Value(signed),
		Claims: claim.Claims{
			Subject:   request.Subject,
			Issuer:    g.issuer,
			Audience:  request.Audience,
			ExpiresAt: &expiresAt,
			IssuedAt:  &now,
			NotBefore: &now,
			Username:  request.Username,
			ID:        id,
			Email:     request.Email,
		},
	}, nil
}

func (g *Generator) resolveTTL(
	ttl *time.Duration,
) (time.Duration, error) {
	if ttl == nil {
		return g.defaultTTL, nil
	}

	value := *ttl

	if value <= 0 {
		return 0, fmt.Errorf(
			"%w: must be positive, got %s",
			errInvalidTTL,
			value,
		)
	}

	if value > g.maxTTL {
		return 0, fmt.Errorf(
			"%w: %s exceeds maximum %s",
			errInvalidTTL,
			value,
			g.maxTTL,
		)
	}

	return value, nil
}

func (g *Generator) signingMethod() jwtlib.SigningMethod {
	switch g.algorithm {
	case AlgorithmRS256:
		return jwtlib.SigningMethodRS256

	default:
		return nil
	}
}

// newJTI generates a 128-bit cryptographically random token identifier.
func newJTI() (string, error) {
	buffer := make([]byte, 16)

	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return hex.EncodeToString(buffer), nil
}
