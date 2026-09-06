package key

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	minimumRSAKeyBits  = 2048
	minimumRSAExponent = 65537
)

// ParsePublic parses one RSA public key from PEM-encoded material.
//
// Only one PEM object is accepted. RSA keys that do not satisfy the
// configured cryptographic-strength policy are rejected.
func ParsePublic(
	pemData []byte,
) (*rsa.PublicKey, error) {
	block, err := decodeSinglePEMBlock(pemData)
	if err != nil {
		return nil, err
	}

	publicKey, err := parsePublicKeyBlock(block)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnexpectedKey
	}

	if err := validateRSAPublicKey(rsaPublicKey); err != nil {
		return nil, err
	}

	return rsaPublicKey, nil
}

func parsePublicKeyBlock(
	block *pem.Block,
) (any, error) {
	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err := x509.ParsePKIXPublicKey(
			block.Bytes,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: parse PKIX public key",
				ErrUnexpectedKey,
			)
		}

		return publicKey, nil

	case "RSA PUBLIC KEY":
		publicKey, err := x509.ParsePKCS1PublicKey(
			block.Bytes,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: parse PKCS#1 public key",
				ErrUnexpectedKey,
			)
		}

		return publicKey, nil

	default:
		return nil, fmt.Errorf(
			"%w: unexpected PEM block type %q",
			ErrUnexpectedKey,
			block.Type,
		)
	}
}

// ParsePrivate parses one RSA private key from PEM-encoded material.
//
// PKCS#1 and PKCS#8 RSA keys are accepted. The parsed key is structurally
// validated and must satisfy the RSA security policy.
func ParsePrivate(
	pemData []byte,
) (*rsa.PrivateKey, error) {
	block, err := decodeSinglePEMBlock(pemData)
	if err != nil {
		return nil, err
	}

	privateKey, err := parsePrivateKeyBlock(block)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrUnexpectedKey
	}

	if err := validateRSAPrivateKey(rsaPrivateKey); err != nil {
		return nil, err
	}

	return rsaPrivateKey, nil
}

func parsePrivateKeyBlock(
	block *pem.Block,
) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(
			block.Bytes,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: parse PKCS#8 private key",
				ErrUnexpectedKey,
			)
		}

		return privateKey, nil

	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(
			block.Bytes,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: parse PKCS#1 private key",
				ErrUnexpectedKey,
			)
		}

		return privateKey, nil

	default:
		return nil, fmt.Errorf(
			"%w: unexpected PEM block type %q",
			ErrUnexpectedKey,
			block.Type,
		)
	}
}

// decodeSinglePEMBlock rejects ambiguous key files containing multiple PEM
// objects or non-whitespace trailing content.
func decodeSinglePEMBlock(
	pemData []byte,
) (*pem.Block, error) {
	block, rest := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf(
			"%w: trailing data after PEM block",
			ErrInvalidPEM,
		)
	}

	return block, nil
}

func validateRSAPrivateKey(
	privateKey *rsa.PrivateKey,
) error {
	if privateKey == nil {
		return ErrInvalidRSAKey
	}

	if err := privateKey.Validate(); err != nil {
		return fmt.Errorf(
			"%w: private key validation failed",
			ErrInvalidRSAKey,
		)
	}

	return validateRSAPublicKey(
		&privateKey.PublicKey,
	)
}

func validateRSAPublicKey(
	publicKey *rsa.PublicKey,
) error {
	if publicKey == nil || publicKey.N == nil {
		return ErrInvalidRSAKey
	}

	bits := publicKey.N.BitLen()
	if bits < minimumRSAKeyBits {
		return fmt.Errorf(
			"%w: modulus is %d bits, minimum is %d",
			ErrInvalidRSAKey,
			bits,
			minimumRSAKeyBits,
		)
	}

	if publicKey.E < minimumRSAExponent ||
		publicKey.E%2 == 0 {
		return fmt.Errorf(
			"%w: public exponent does not satisfy policy",
			ErrInvalidRSAKey,
		)
	}

	return nil
}

// isSupportedAlgorithm reports whether the key layer supports the exact
// algorithm requested by the JWT implementation.
func isSupportedAlgorithm(
	algorithm string,
) bool {
	return algorithm == "RS256"
}
