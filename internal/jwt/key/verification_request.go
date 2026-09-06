package key

// VerificationRequest describes what the parser needs from a verification
// provider in order to verify a token's signature.
type VerificationRequest struct {
	Algorithm string
}
