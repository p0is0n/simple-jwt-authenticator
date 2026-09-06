package claim

import "fmt"

// Name identifies a normalized token claim that can participate in a claim
// expression.
type Name string

const (
	// NameSubject identifies the subject claim.
	NameSubject Name = "subject"

	// NameIssuer identifies the issuer claim.
	NameIssuer Name = "issuer"

	// NameAudience identifies the audience claim.
	NameAudience Name = "audience"

	// NameID identifies the token identifier claim.
	NameID Name = "id"

	// NameUsername identifies the username claim.
	NameUsername Name = "username"

	// NameEmail identifies the email claim.
	NameEmail Name = "email"
)

// ParseName parses an external claim name into its typed representation.
//
// Unsupported names are rejected explicitly rather than ignored so callers
// cannot accidentally construct a policy for a claim that the expression
// engine does not evaluate.
func ParseName(
	value string,
) (Name, error) {
	name := Name(value)
	if !name.isSupported() {
		return "", fmt.Errorf(
			"%w: %q",
			ErrInvalidName,
			value,
		)
	}

	return name, nil
}

func (n Name) isSupported() bool {
	switch n {
	case NameSubject,
		NameIssuer,
		NameAudience,
		NameID,
		NameUsername,
		NameEmail:
		return true

	default:
		return false
	}
}
