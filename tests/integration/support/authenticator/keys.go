//go:build integration

package authenticator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// KeyPair holds a generated RSA test key pair and the path of the written
// public key PEM file.
type KeyPair struct {
	// PrivateKey signs test tokens. It stays on the machine running the
	// tests and is never copied into the authenticator container.
	PrivateKey *rsa.PrivateKey

	// PublicKeyPath is the path of the PEM-encoded public key on the
	// machine running the tests.
	PublicKeyPath string
}

// GenerateKeyPair generates an RSA-2048 key pair for integration tests and
// writes the PEM files into dir.
//
// The caller owns dir and is responsible for removing it after all
// resources using the generated files have been stopped.
func GenerateKeyPair(dir string) (KeyPair, error) {
	if dir == "" {
		return KeyPair{}, fmt.Errorf("key directory is required")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate RSA key pair: %w", err)
	}

	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("marshal public key: %w", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateDER,
	})

	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	})

	privatePath := filepath.Join(dir, "jwt-private.pem")
	publicPath := filepath.Join(dir, "jwt-public.pem")

	// The private key never leaves the test machine and is only read by
	// the integration-test process.
	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		return KeyPair{}, fmt.Errorf("write private key: %w", err)
	}

	// The public key is mounted into the authenticator container and must
	// be readable by its non-root runtime user.
	if err := os.WriteFile(publicPath, publicPEM, 0o644); err != nil {
		return KeyPair{}, fmt.Errorf("write public key: %w", err)
	}

	return KeyPair{
		PrivateKey:    privateKey,
		PublicKeyPath: publicPath,
	}, nil
}
