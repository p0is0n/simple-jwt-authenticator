package key

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

func generateRSAKey(
	t *testing.T,
) *rsa.PrivateKey {
	t.Helper()

	return generateRSAKeyWithBits(
		t,
		minimumRSAKeyBits,
	)
}

func generateRSAKeyWithBits(
	t *testing.T,
	bits int,
) *rsa.PrivateKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(
		testRand(),
		bits,
	)
	if err != nil {
		t.Fatalf(
			"rsa.GenerateKey() error = %v, want nil",
			err,
		)
	}

	return privateKey
}

func publicKeyPEM(
	t *testing.T,
	publicKey *rsa.PublicKey,
) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(
		publicKey,
	)
	if err != nil {
		t.Fatalf(
			"x509.MarshalPKIXPublicKey() error = %v, want nil",
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

func privateKeyPKCS1PEM(
	t *testing.T,
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

func privateKeyPKCS8PEM(
	t *testing.T,
	privateKey *rsa.PrivateKey,
) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(
		privateKey,
	)
	if err != nil {
		t.Fatalf(
			"x509.MarshalPKCS8PrivateKey() error = %v, want nil",
			err,
		)
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		},
	)
}

func TestParsePublic_Valid(t *testing.T) {
	privateKey := generateRSAKey(t)

	parsed, err := ParsePublic(
		publicKeyPEM(
			t,
			&privateKey.PublicKey,
		),
	)
	if err != nil {
		t.Fatalf(
			"ParsePublic() error = %v, want nil",
			err,
		)
	}

	if parsed.N.Cmp(privateKey.N) != 0 {
		t.Fatal("parsed public key modulus differs from source key")
	}
}

func TestParsePublic_InvalidPEM(t *testing.T) {
	_, err := ParsePublic(
		[]byte("not a pem"),
	)

	if !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf(
			"ParsePublic() error = %v, want ErrInvalidPEM",
			err,
		)
	}
}

func TestParsePublic_UnexpectedBlockType(t *testing.T) {
	privateKey := generateRSAKey(t)

	_, err := ParsePublic(
		privateKeyPKCS1PEM(
			t,
			privateKey,
		),
	)

	if !errors.Is(err, ErrUnexpectedKey) {
		t.Fatalf(
			"ParsePublic() error = %v, want ErrUnexpectedKey",
			err,
		)
	}
}

func TestParsePublic_WeakRSAKeyRejected(t *testing.T) {
	privateKey := generateRSAKeyWithBits(
		t,
		1024,
	)

	_, err := ParsePublic(
		publicKeyPEM(
			t,
			&privateKey.PublicKey,
		),
	)

	if !errors.Is(err, ErrInvalidRSAKey) {
		t.Fatalf(
			"ParsePublic() error = %v, want ErrInvalidRSAKey",
			err,
		)
	}
}

func TestParsePublic_TrailingDataRejected(t *testing.T) {
	privateKey := generateRSAKey(t)

	data := append(
		publicKeyPEM(
			t,
			&privateKey.PublicKey,
		),
		[]byte("unexpected trailing material")...,
	)

	_, err := ParsePublic(data)

	if !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf(
			"ParsePublic() error = %v, want ErrInvalidPEM",
			err,
		)
	}
}

func TestParsePublic_MultiplePEMBlocksRejected(t *testing.T) {
	first := generateRSAKey(t)
	second := generateRSAKey(t)

	data := append(
		publicKeyPEM(
			t,
			&first.PublicKey,
		),
		publicKeyPEM(
			t,
			&second.PublicKey,
		)...,
	)

	_, err := ParsePublic(data)

	if !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf(
			"ParsePublic() error = %v, want ErrInvalidPEM",
			err,
		)
	}
}

func TestParsePrivate_PKCS1Valid(t *testing.T) {
	privateKey := generateRSAKey(t)

	parsed, err := ParsePrivate(
		privateKeyPKCS1PEM(
			t,
			privateKey,
		),
	)
	if err != nil {
		t.Fatalf(
			"ParsePrivate() error = %v, want nil",
			err,
		)
	}

	if parsed.N.Cmp(privateKey.N) != 0 {
		t.Fatal("parsed private key modulus differs from source key")
	}
}

func TestParsePrivate_PKCS8Valid(t *testing.T) {
	privateKey := generateRSAKey(t)

	parsed, err := ParsePrivate(
		privateKeyPKCS8PEM(
			t,
			privateKey,
		),
	)
	if err != nil {
		t.Fatalf(
			"ParsePrivate() error = %v, want nil",
			err,
		)
	}

	if parsed.N.Cmp(privateKey.N) != 0 {
		t.Fatal("parsed private key modulus differs from source key")
	}
}

func TestParsePrivate_InvalidPEM(t *testing.T) {
	_, err := ParsePrivate(
		[]byte("not a pem"),
	)

	if !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf(
			"ParsePrivate() error = %v, want ErrInvalidPEM",
			err,
		)
	}
}

func TestParsePrivate_WeakRSAKeyRejected(t *testing.T) {
	privateKey := generateRSAKeyWithBits(
		t,
		1024,
	)

	_, err := ParsePrivate(
		privateKeyPKCS1PEM(
			t,
			privateKey,
		),
	)

	if !errors.Is(err, ErrInvalidRSAKey) {
		t.Fatalf(
			"ParsePrivate() error = %v, want ErrInvalidRSAKey",
			err,
		)
	}
}

func TestParsePrivate_ErrorsDoNotLeakPEM(t *testing.T) {
	bad := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte("not a real key"),
		},
	)

	_, err := ParsePrivate(bad)
	if err == nil {
		t.Fatal("ParsePrivate() error = nil, want non-nil")
	}

	if !errors.Is(err, ErrUnexpectedKey) {
		t.Fatalf(
			"ParsePrivate() error = %v, want ErrUnexpectedKey",
			err,
		)
	}
}
