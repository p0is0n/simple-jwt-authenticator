package server

import (
	"fmt"
	"os"

	"simple-jwt-authenticator/internal/config"
)

// Load reads and strictly decodes a server configuration file.
//
// Server defaults are initialized before decoding. Fields explicitly present
// in the YAML document override those defaults.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf(
			"read server config %q: %w",
			path,
			err,
		)
	}

	appConfig, err := LoadFromBytes(data)
	if err != nil {
		return Config{}, fmt.Errorf(
			"decode server config %q: %w",
			path,
			err,
		)
	}

	return appConfig, nil
}

// LoadFromBytes strictly decodes a server configuration document.
//
// Decoding starts from the complete server defaults and applies the YAML
// document as an override. This preserves explicit zero values such as false
// while still supplying defaults for omitted fields.
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
