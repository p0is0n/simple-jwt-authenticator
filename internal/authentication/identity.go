package authentication

// Identity is the normalized authenticated identity derived from validated
// token claims.
//
// Subject is the stable required identity. Username and Email are optional
// human-friendly fields, allowing machine identities to be represented
// without them.
type Identity struct {
	Subject  string `json:"subject"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
}
