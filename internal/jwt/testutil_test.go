package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// testKeys generates a test RSA key pair.
func testKeys(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatalf(
			"generate rsa key: %v",
			err,
		)
	}

	return privateKey
}

// signTokenWith builds a token signed with a chosen algorithm and a
// claims-building function, returning the encoded token string.
func signTokenWith(
	t testing.TB,
	signer jwtlib.SigningMethod,
	privateKey *rsa.PrivateKey,
	build func(registered *jwtlib.RegisteredClaims) claims,
) string {
	t.Helper()

	registered := jwtlib.RegisteredClaims{}
	generated := build(&registered)

	token := jwtlib.NewWithClaims(
		signer,
		generated,
	)

	signed, err := token.SignedString(
		privateKey,
	)
	if err != nil {
		t.Fatalf(
			"sign token: %v",
			err,
		)
	}

	return signed
}

// signValidToken builds a valid RS256 token with the given subject and
// claims, valid for an hour from now.
func signValidToken(
	t testing.TB,
	privateKey *rsa.PrivateKey,
	subject string,
) string {
	t.Helper()

	now := time.Now().UTC()

	return signTokenWith(
		t,
		jwtlib.SigningMethodRS256,
		privateKey,
		func(
			registered *jwtlib.RegisteredClaims,
		) claims {
			registered.Subject = subject
			registered.ExpiresAt = jwtlib.NewNumericDate(
				now.Add(
					time.Hour,
				),
			)
			registered.IssuedAt = jwtlib.NewNumericDate(
				now,
			)
			registered.NotBefore = jwtlib.NewNumericDate(
				now,
			)

			return claims{
				RegisteredClaims: *registered,
				Username:         "front",
				Email:            "front@example.com",
			}
		},
	)
}

// signNoneToken builds a token with the "none" algorithm.
func signNoneToken(
	t testing.TB,
	subject string,
) string {
	t.Helper()

	now := time.Now().UTC()

	token := jwtlib.NewWithClaims(
		jwtlib.SigningMethodNone,
		jwtlib.RegisteredClaims{
			Subject: subject,
			ExpiresAt: jwtlib.NewNumericDate(
				now.Add(
					time.Hour,
				),
			),
			IssuedAt: jwtlib.NewNumericDate(
				now,
			),
		},
	)

	signed, err := token.SignedString(
		jwtlib.UnsafeAllowNoneSignatureType,
	)
	if err != nil {
		t.Fatalf(
			"sign none token: %v",
			err,
		)
	}

	return signed
}

// signHS256Token builds an HS256 token using a symmetric secret. Used to
// verify algorithm-confusion rejection.
func signHS256Token(
	t testing.TB,
	secret []byte,
	subject string,
) string {
	t.Helper()

	now := time.Now().UTC()

	token := jwtlib.NewWithClaims(
		jwtlib.SigningMethodHS256,
		jwtlib.RegisteredClaims{
			Subject: subject,
			ExpiresAt: jwtlib.NewNumericDate(
				now.Add(
					time.Hour,
				),
			),
			IssuedAt: jwtlib.NewNumericDate(
				now,
			),
		},
	)

	signed, err := token.SignedString(
		secret,
	)
	if err != nil {
		t.Fatalf(
			"sign hs256 token: %v",
			err,
		)
	}

	return signed
}

// signWrongRSAAlgorithm builds an RS512 token.
func signWrongRSAAlgorithm(
	t testing.TB,
	privateKey *rsa.PrivateKey,
	subject string,
) string {
	t.Helper()

	now := time.Now().UTC()

	token := jwtlib.NewWithClaims(
		jwtlib.SigningMethodRS512,
		jwtlib.RegisteredClaims{
			Subject: subject,
			ExpiresAt: jwtlib.NewNumericDate(
				now.Add(
					time.Hour,
				),
			),
			IssuedAt: jwtlib.NewNumericDate(
				now,
			),
		},
	)

	signed, err := token.SignedString(
		privateKey,
	)
	if err != nil {
		t.Fatalf(
			"sign rs512 token: %v",
			err,
		)
	}

	return signed
}

// signWithDifferentKey builds a valid RS256 token signed with a different
// key pair.
func signWithDifferentKey(
	t testing.TB,
	subject string,
) string {
	t.Helper()

	other := testKeys(t)

	return signValidToken(
		t,
		other,
		subject,
	)
}

// publicKeyPKIXPEM encodes a public key to PKIX PEM for parser tests.
func publicKeyPKIXPEM(
	t testing.TB,
	privateKey *rsa.PrivateKey,
) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(
		&privateKey.PublicKey,
	)
	if err != nil {
		t.Fatalf(
			"marshal pkix public key: %v",
			err,
		)
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		},
	)
}

// optionalClaimsToken builds an RS256 token with only subject and exp.
func optionalClaimsToken(
	t testing.TB,
	privateKey *rsa.PrivateKey,
	subject string,
) string {
	t.Helper()

	now := time.Now().UTC()

	return signTokenWith(
		t,
		jwtlib.SigningMethodRS256,
		privateKey,
		func(
			registered *jwtlib.RegisteredClaims,
		) claims {
			registered.Subject = subject
			registered.ExpiresAt = jwtlib.NewNumericDate(
				now.Add(
					time.Hour,
				),
			)

			return claims{
				RegisteredClaims: *registered,
			}
		},
	)
}

// privateKeyPKCS1PEMBytes encodes a private key to PKCS#1 PEM bytes for
// generator tests.
func privateKeyPKCS1PEMBytes(
	t testing.TB,
	privateKey *rsa.PrivateKey,
) []byte {
	t.Helper()

	return pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(
				privateKey,
			),
		},
	)
}
