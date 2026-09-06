package key

import (
	"crypto/rsa"
	"fmt"
	"os"
)

// LoadPublic loads and parses an RSA public key from exactly one configured
// source.
//
// Inline material and a file path are mutually exclusive. Key material itself
// is never included in returned errors.
func LoadPublic(
	inline string,
	filePath string,
) (*rsa.PublicKey, error) {
	material, err := readMaterial(
		inline,
		filePath,
		"public key",
	)
	if err != nil {
		return nil, err
	}

	publicKey, err := ParsePublic(
		material,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse public key: %w",
			err,
		)
	}

	return publicKey, nil
}

// LoadPrivate loads and parses an RSA private key from exactly one configured
// source.
//
// Inline material and a file path are mutually exclusive. Key material itself
// is never included in returned errors.
func LoadPrivate(
	inline string,
	filePath string,
) (*rsa.PrivateKey, error) {
	material, err := readMaterial(
		inline,
		filePath,
		"private key",
	)
	if err != nil {
		return nil, err
	}

	privateKey, err := ParsePrivate(
		material,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse private key: %w",
			err,
		)
	}

	return privateKey, nil
}

// readMaterial resolves non-empty key material from exactly one source.
//
// Configuration validation is expected to enforce the same invariant, but it
// is intentionally checked again here because key loading is a
// security-sensitive boundary and must remain safe for direct callers.
func readMaterial(
	inline string,
	filePath string,
	description string,
) ([]byte, error) {
	switch {
	case inline != "" && filePath != "":
		return nil, fmt.Errorf(
			"%s: exactly one key source must be configured",
			description,
		)

	case inline != "":
		return []byte(inline), nil

	case filePath == "":
		return nil, fmt.Errorf(
			"%s: no key source configured",
			description,
		)
	}

	data, err := os.ReadFile(
		filePath,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read %s file %q: %w",
			description,
			filePath,
			err,
		)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf(
			"%s file %q is empty",
			description,
			filePath,
		)
	}

	return data, nil
}
