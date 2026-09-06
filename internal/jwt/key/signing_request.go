package key

// SigningRequest describes what the generator needs from a signing
// provider in order to sign a token.
type SigningRequest struct {
	Algorithm string
}
