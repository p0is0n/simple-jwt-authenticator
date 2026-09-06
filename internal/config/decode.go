// Package config defines shared configuration contracts and strict decoding
// primitives used by application-specific configuration packages.
package config

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// DecodeStrict decodes exactly one non-empty YAML document into T.
//
// Unknown YAML fields are rejected. An empty document is rejected because
// there is no existing configuration state for it to override.
func DecodeStrict[T any](data []byte) (T, error) {
	var value T

	empty, err := decodeStrictInto(
		data,
		&value,
	)
	if err != nil {
		return value, err
	}

	if empty {
		return value, fmt.Errorf(
			"configuration document is empty",
		)
	}

	return value, nil
}

// DecodeStrictInto decodes at most one YAML document into value.
//
// Fields already initialized in value are preserved when they are omitted
// from the YAML document. An empty document is therefore valid and leaves
// value unchanged.
//
// Unknown YAML fields are rejected and multiple YAML documents are not
// supported.
func DecodeStrictInto[T any](
	data []byte,
	value *T,
) error {
	if value == nil {
		return fmt.Errorf(
			"configuration destination must not be nil",
		)
	}

	_, err := decodeStrictInto(
		data,
		value,
	)

	return err
}

// decodeStrictInto decodes at most one YAML document into value and reports
// whether the input contained no document.
func decodeStrictInto[T any](
	data []byte,
	value *T,
) (bool, error) {
	decoder := yaml.NewDecoder(
		bytes.NewReader(data),
	)
	decoder.KnownFields(true)

	if err := decoder.Decode(value); err != nil {
		if err == io.EOF {
			return true, nil
		}

		return false, err
	}

	var extra any

	switch err := decoder.Decode(&extra); err {
	case io.EOF:
		return false, nil

	case nil:
		return false, fmt.Errorf(
			"multiple YAML documents are not supported",
		)

	default:
		return false, err
	}
}
