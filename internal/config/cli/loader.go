package cli

import (
	"fmt"
	"os"

	"simple-jwt-authenticator/internal/config"
)

// Load reads and strictly decodes a CLI configuration file.
//
// CLI defaults are initialized before decoding. Fields explicitly present in
// the YAML document override those defaults.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf(
			"read CLI config %q: %w",
			path,
			err,
		)
	}

	appConfig, err := LoadFromBytes(data)
	if err != nil {
		return Config{}, fmt.Errorf(
			"decode CLI config %q: %w",
			path,
			err,
		)
	}

	return appConfig, nil
}

// LoadFromBytes strictly decodes a CLI configuration document.
//
// Decoding starts from the complete CLI defaults and applies the YAML
// document as an override. Security-sensitive fields that have no defaults
// remain unset unless explicitly configured.
func LoadFromBytes(data []byte) (Config, error) {
	appConfig := defaultConfig()

	if err := config.DecodeStrictInto(
		data,
		&appConfig,
	); err != nil {
		return Config{}, err
	}

	return appConfig, nil
}
