package config

// Supported JWT algorithms.
const (
	JWTAlgorithmRS256 = "RS256"
)

// JWTVerification contains configuration required to verify JWTs.
//
// It intentionally contains no private signing material.
type JWTVerification struct {
	Algorithm     string   `yaml:"algorithm"`
	PublicKeyPEM  string   `yaml:"public_key_pem"`
	PublicKeyFile string   `yaml:"public_key_file"`
	Issuer        string   `yaml:"issuer"`
	Audience      []string `yaml:"audience"`
	ClockSkew     Duration `yaml:"clock_skew"`
}

// JWTSigning contains configuration used only for JWT generation.
//
// Algorithm and issuer are shared with JWTVerification by the CLI's flat JWT
// configuration and are therefore intentionally not duplicated here.
//
// These fields must never become part of the server configuration schema.
type JWTSigning struct {
	PrivateKeyPEM  string   `yaml:"private_key_pem"`
	PrivateKeyFile string   `yaml:"private_key_file"`
	DefaultTTL     Duration `yaml:"default_ttl"`
	MaxTTL         Duration `yaml:"max_ttl"`
}
