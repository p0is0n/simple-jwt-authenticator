package jwt

import (
	"context"
	"errors"
	"fmt"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"simple-jwt-authenticator/internal/jwt/key"
	"simple-jwt-authenticator/internal/token"
)

const maxTokenLength = 16 * 1024

// Parser is the concrete JWT parser. It implements token.Parser.
//
// Parser owns JWT syntax parsing, algorithm enforcement, verification-key
// resolution, signature verification, and normalization into token.Claims.
//
// Application policy such as expiration, issuer, audience, and required
// identity claims is intentionally handled by the validator layer.
type Parser struct {
	verificationProvider key.VerificationProvider
	algorithm            Algorithm
	parser               *jwtlib.Parser
}

// NewParser constructs a Parser bound to one explicitly permitted algorithm
// and a verification provider.
func NewParser(
	verificationProvider key.VerificationProvider,
	algorithm Algorithm,
) (*Parser, error) {
	if verificationProvider == nil {
		return nil, fmt.Errorf(
			"create jwt parser: %w",
			errNilVerificationProvider,
		)
	}

	if err := algorithm.validate(); err != nil {
		return nil, fmt.Errorf(
			"create jwt parser: %w",
			err,
		)
	}

	jwtParser := jwtlib.NewParser(
		jwtlib.WithValidMethods(
			[]string{
				algorithm.String(),
			},
		),
		jwtlib.WithStrictDecoding(),
		jwtlib.WithoutClaimsValidation(),
	)

	return &Parser{
		verificationProvider: verificationProvider,
		algorithm:            algorithm,
		parser:               jwtParser,
	}, nil
}

// Parse implements token.Parser.
func (p *Parser) Parse(
	ctx context.Context,
	request token.ParseRequest,
) (token.Token, error) {
	if err := ctx.Err(); err != nil {
		return token.Token{}, err
	}

	if request.Value == "" {
		return token.Token{}, fmt.Errorf(
			"%w: empty token",
			token.ErrMalformedToken,
		)
	}

	if len(request.Value) > maxTokenLength {
		return token.Token{}, fmt.Errorf(
			"%w: token exceeds maximum supported size",
			token.ErrMalformedToken,
		)
	}

	parsedClaims := claims{}

	jwtToken, err := p.parser.ParseWithClaims(
		string(request.Value),
		&parsedClaims,
		p.keyFunc(ctx),
	)
	if err != nil {
		if p.hasUnsupportedMethod(jwtToken) {
			return token.Token{}, fmt.Errorf(
				"%w: token signing method is not permitted",
				token.ErrUnsupportedAlgorithm,
			)
		}

		return token.Token{}, mapParseError(err)
	}

	if jwtToken == nil ||
		jwtToken.Method == nil ||
		!jwtToken.Valid {
		return token.Token{}, fmt.Errorf(
			"%w: token verification did not produce a valid token",
			token.ErrInvalidSignature,
		)
	}

	// Defense in depth. WithValidMethods and keyFunc enforce the same policy
	// earlier, but a successful parse must still end with the exact signing
	// implementation expected by this parser.
	if !p.acceptsMethod(jwtToken.Method) {
		return token.Token{}, fmt.Errorf(
			"%w: token signing method is not permitted",
			token.ErrUnsupportedAlgorithm,
		)
	}

	return token.Token{
		Claims: parsedClaims.toToken(),
	}, nil
}

// keyFunc resolves verification material only after the exact configured
// signing method has been established.
//
// The token-supplied alg value never selects a different verification
// algorithm or key family.
func (p *Parser) keyFunc(
	ctx context.Context,
) jwtlib.Keyfunc {
	return func(jwtToken *jwtlib.Token) (any, error) {
		if jwtToken == nil || jwtToken.Method == nil {
			return nil, fmt.Errorf(
				"%w: missing signing method",
				token.ErrUnsupportedAlgorithm,
			)
		}

		if !p.acceptsMethod(jwtToken.Method) {
			return nil, fmt.Errorf(
				"%w: token signing method is not permitted",
				token.ErrUnsupportedAlgorithm,
			)
		}

		verificationKey, err := p.verificationProvider.Provide(
			ctx,
			key.VerificationRequest{
				Algorithm: p.algorithm.String(),
			},
		)
		if err != nil {
			return nil, fmt.Errorf(
				"obtain verification key: %w",
				err,
			)
		}

		return verificationKey, nil
	}
}

// acceptsMethod verifies both the algorithm name and the concrete signing
// implementation.
//
// Checking the concrete implementation prevents another signing method
// registered under the same algorithm name from silently becoming trusted.
func (p *Parser) acceptsMethod(
	method jwtlib.SigningMethod,
) bool {
	switch p.algorithm {
	case AlgorithmRS256:
		return method == jwtlib.SigningMethodRS256

	default:
		return false
	}
}

// hasUnsupportedMethod determines whether a partially parsed token declared
// or resolved to a signing method outside this parser's policy.
//
// ParseWithClaims may return a token together with an error. Information from
// that token is used only to classify the failure and never to authenticate
// it.
func (p *Parser) hasUnsupportedMethod(
	jwtToken *jwtlib.Token,
) bool {
	if jwtToken == nil {
		return false
	}

	if jwtToken.Method != nil {
		return !p.acceptsMethod(jwtToken.Method)
	}

	algorithm, ok := jwtToken.Header["alg"].(string)
	if !ok {
		return false
	}

	return algorithm != p.algorithm.String()
}

// mapParseError translates JWT-library errors into bounded token errors while
// preserving unexpected infrastructure failures in the error chain.
func mapParseError(err error) error {
	switch {
	case errors.Is(err, token.ErrUnsupportedAlgorithm):
		return err

	case errors.Is(err, jwtlib.ErrTokenInvalidClaims),
		errors.Is(err, jwtlib.ErrInvalidType):
		return fmt.Errorf(
			"%w: %w",
			token.ErrInvalidClaims,
			err,
		)

	case errors.Is(err, jwtlib.ErrTokenMalformed):
		return fmt.Errorf(
			"%w: %w",
			token.ErrMalformedToken,
			err,
		)

	case errors.Is(err, jwtlib.ErrTokenSignatureInvalid):
		return fmt.Errorf(
			"%w: %w",
			token.ErrInvalidSignature,
			err,
		)

	case errors.Is(err, jwtlib.ErrTokenUnverifiable):
		// An unverifiable token can be caused by verification-key
		// infrastructure failures. Do not misclassify those failures as
		// an unsupported client-selected algorithm.
		return fmt.Errorf(
			"token unverifiable: %w",
			err,
		)

	default:
		return fmt.Errorf(
			"%w: %w",
			token.ErrMalformedToken,
			err,
		)
	}
}
