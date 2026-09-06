//go:build integration

package authenticator

import (
	"fmt"
	"os"
	"path/filepath"
)

// MetricsPath is the metrics endpoint path configured for the
// integration-test authenticator and used by metrics integration tests.
const MetricsPath = "/metrics_not_standart"

// DefaultIssuer is the JWT issuer configured for the integration-test
// authenticator. Token builders must use the same issuer.
const DefaultIssuer = "home-auth"

// containerConfigPath is the container path of the configuration file.
const containerConfigPath = "/config/config.yaml"

// containerPublicKeyPath is the container path where the public
// verification key is copied.
const containerPublicKeyPath = "/config/jwt-public.pem"

// configFileMode makes the copied configuration and public key readable by
// the non-root user inside the container.
const configFileMode = 0o644

// writeConfig writes the server-mode configuration for the integration-test
// authenticator into dir and returns the host path of the written file.
//
// The caller owns dir and is responsible for removing it after all resources
// using the configuration have been stopped.
//
// The server configuration contains verification material only. The public
// verification key is referenced by its container path and copied into the
// container separately. Signing configuration and private key material are
// deliberately absent because the server must never require or accept them.
func writeConfig(
	dir string,
) (string, error) {
	if dir == "" {
		return "", fmt.Errorf(
			"config directory is required",
		)
	}

	content := fmt.Sprintf(`
jwt:
  algorithm: "RS256"
  public_key_file: %q
  issuer: %q
  audience:
    - "internal-services"
  clock_skew: 30s

auth:
  handlers:
    http:
      nginx:
        enabled: true
  extractors:
    http:
      authorization_header:
        enabled: true
      cookie:
        enabled: true
        name: "auth_token_test"

metrics:
  enabled: true
  path: %q
`,
		containerPublicKeyPath,
		DefaultIssuer,
		MetricsPath,
	)

	path := filepath.Join(
		dir,
		"config.yaml",
	)

	if err := os.WriteFile(
		path,
		[]byte(content),
		configFileMode,
	); err != nil {
		return "", fmt.Errorf(
			"write authenticator config: %w",
			err,
		)
	}

	return path, nil
}
