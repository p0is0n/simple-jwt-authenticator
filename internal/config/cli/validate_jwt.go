package cli

import (
	"simple-jwt-authenticator/internal/config/validation"
)

func validateTokenValidateJWT(
	jwt JWT,
) error {
	return validation.ValidateJWTVerification(
		jwt.JWTVerification,
	)
}

func validateTokenGenerateJWT(
	jwt JWT,
) error {
	return validation.ValidateJWTSigning(
		jwt.Algorithm,
		jwt.Issuer,
		jwt.JWTSigning,
	)
}
