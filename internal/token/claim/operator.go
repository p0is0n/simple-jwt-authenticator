package claim

import "fmt"

// Operator identifies a comparison operation applied to a normalized claim
// value.
type Operator string

const (
	// OperatorEqual performs exact, case-sensitive string equality.
	OperatorEqual Operator = "eq"

	// OperatorRegex matches a claim value against a regular expression.
	//
	// Patterns use Go's regexp syntax, which is based on RE2 and does not
	// support backtracking-based expressions.
	OperatorRegex Operator = "regex"
)

// ParseOperator parses an external operator name into its typed
// representation.
//
// Unsupported operators are rejected explicitly so callers cannot construct
// expressions with undefined comparison semantics.
func ParseOperator(
	value string,
) (Operator, error) {
	operator := Operator(value)
	if !operator.isSupported() {
		return "", fmt.Errorf(
			"%w: %q",
			ErrInvalidOperator,
			value,
		)
	}

	return operator, nil
}

func (o Operator) isSupported() bool {
	switch o {
	case OperatorEqual,
		OperatorRegex:
		return true

	default:
		return false
	}
}
