package validation

import (
	"errors"
	"fmt"
	"strings"

	"simple-jwt-authenticator/internal/config"
)

// ValidateJWTVerification validates configuration required to verify JWTs.
func ValidateJWTVerification(
	jwt config.JWTVerification,
) error {
	var problems []error

	if err := ValidateJWTAlgorithm(
		jwt.Algorithm,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if err := SingleKeySource(
		"jwt.public_key_pem",
		"jwt.public_key_file",
		jwt.PublicKeyPEM,
		jwt.PublicKeyFile,
		true,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if err := CanonicalNonEmptyString(
		"jwt.issuer",
		jwt.Issuer,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if err := Audience(
		"jwt.audience",
		jwt.Audience,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if err := NonNegativeDuration(
		"jwt.clock_skew",
		jwt.ClockSkew,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	return errors.Join(
		problems...,
	)
}

// ValidateJWTSigning validates configuration required to sign JWTs.
func ValidateJWTSigning(
	algorithm string,
	issuer string,
	signing config.JWTSigning,
) error {
	var problems []error

	if err := ValidateJWTAlgorithm(
		algorithm,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if err := SingleKeySource(
		"jwt.private_key_pem",
		"jwt.private_key_file",
		signing.PrivateKeyPEM,
		signing.PrivateKeyFile,
		true,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if err := CanonicalNonEmptyString(
		"jwt.issuer",
		issuer,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if err := PositiveDuration(
		"jwt.default_ttl",
		signing.DefaultTTL,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if err := PositiveDuration(
		"jwt.max_ttl",
		signing.MaxTTL,
	); err != nil {
		problems = append(
			problems,
			err,
		)
	}

	if signing.DefaultTTL.Std() > 0 &&
		signing.MaxTTL.Std() > 0 &&
		signing.DefaultTTL.Std() > signing.MaxTTL.Std() {
		problems = append(
			problems,
			fmt.Errorf(
				"jwt.default_ttl (%s) must not exceed jwt.max_ttl (%s)",
				signing.DefaultTTL,
				signing.MaxTTL,
			),
		)
	}

	return errors.Join(
		problems...,
	)
}

// ValidateJWTAlgorithm validates the configured JWT signing algorithm.
func ValidateJWTAlgorithm(
	value string,
) error {
	if value != config.JWTAlgorithmRS256 {
		return fmt.Errorf(
			"jwt.algorithm must be %s, got %q",
			config.JWTAlgorithmRS256,
			value,
		)
	}

	return nil
}

// SingleKeySource validates an inline/file key source pair.
//
// When required is true, exactly one source must be configured. When false,
// both may be absent, but configuring both is always rejected.
func SingleKeySource(
	inlineField string,
	fileField string,
	inlineValue string,
	fileValue string,
	required bool,
) error {
	var problems []error

	inlineConfigured := inlineValue != ""
	fileConfigured := fileValue != ""

	if inlineConfigured &&
		strings.TrimSpace(inlineValue) == "" {
		problems = append(
			problems,
			fmt.Errorf(
				"%s must not contain only whitespace",
				inlineField,
			),
		)
	}

	if fileConfigured {
		if err := CanonicalNonEmptyString(
			fileField,
			fileValue,
		); err != nil {
			problems = append(
				problems,
				err,
			)
		}
	}

	if inlineConfigured && fileConfigured {
		problems = append(
			problems,
			fmt.Errorf(
				"%s and %s are mutually exclusive, configure exactly one",
				inlineField,
				fileField,
			),
		)
	}

	if required &&
		!inlineConfigured &&
		!fileConfigured {
		problems = append(
			problems,
			fmt.Errorf(
				"one of %s or %s must be configured",
				inlineField,
				fileField,
			),
		)
	}

	return errors.Join(
		problems...,
	)
}

// Audience validates an expected JWT audience set.
func Audience(
	field string,
	audience []string,
) error {
	if len(audience) == 0 {
		return nil
	}

	var problems []error

	seen := make(
		map[string]struct{},
		len(audience),
	)

	for index, value := range audience {
		entryField := fmt.Sprintf(
			"%s[%d]",
			field,
			index,
		)

		if err := CanonicalNonEmptyString(
			entryField,
			value,
		); err != nil {
			problems = append(
				problems,
				err,
			)

			continue
		}

		if _, exists := seen[value]; exists {
			problems = append(
				problems,
				fmt.Errorf(
					"%s duplicates audience %q",
					entryField,
					value,
				),
			)

			continue
		}

		seen[value] = struct{}{}
	}

	return errors.Join(
		problems...,
	)
}
