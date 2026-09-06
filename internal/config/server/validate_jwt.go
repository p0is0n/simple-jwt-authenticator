package server

import (
	"simple-jwt-authenticator/internal/config"
	"simple-jwt-authenticator/internal/config/validation"
)

func validateJWT(
	jwt config.JWTVerification,
) error {
	return validation.ValidateJWTVerification(
		jwt,
	)
}
