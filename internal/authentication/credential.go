package authentication

import "simple-jwt-authenticator/internal/token"

// Credential contains only the value required for authentication. It must
// not carry transport source information.
type Credential struct {
	Value token.Value
}
