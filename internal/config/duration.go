package config

import (
	"fmt"
	"time"
)

// Duration is a configuration duration that decodes from YAML as a plain
// time.Duration string, for example "5s" or "1h".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var value string

	if err := unmarshal(&value); err != nil {
		return err
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf(
			"parse duration %q: %w",
			value,
			err,
		)
	}

	*d = Duration(parsed)

	return nil
}

// Std returns the standard-library representation.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// String returns the canonical duration representation.
func (d Duration) String() string {
	return time.Duration(d).String()
}
