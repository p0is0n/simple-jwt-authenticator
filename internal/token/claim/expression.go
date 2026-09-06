package claim

import (
	"fmt"
	"regexp"
)

const (
	// maxExpressionDepth limits logical-expression nesting to bound evaluation
	// cost and protect parsers from constructing excessively deep policies.
	maxExpressionDepth = 16

	// maxExpressionNodes limits the total number of logical and match nodes in
	// a single expression tree.
	maxExpressionNodes = 64

	// maxMatchValueBytes limits comparison values and regular-expression
	// patterns before they are stored or compiled.
	maxMatchValueBytes = 1024
)

// Expression is a validated boolean expression evaluated against normalized
// token claims.
//
// The interface is intentionally sealed. Expressions can only be constructed
// through this package's constructors, which enforce structural and resource
// limits before an expression can be evaluated.
type Expression interface {
	evaluate(
		claims Claims,
	) bool

	stats() expressionStats

	isExpression()
}

type expressionStats struct {
	depth int
	nodes int
}

type allExpression struct {
	expressions []Expression
	statistics  expressionStats
}

func (*allExpression) isExpression() {}

func (e *allExpression) stats() expressionStats {
	return e.statistics
}

func (e *allExpression) evaluate(
	claims Claims,
) bool {
	for _, expression := range e.expressions {
		if !expression.evaluate(
			claims,
		) {
			return false
		}
	}

	return true
}

type anyExpression struct {
	expressions []Expression
	statistics  expressionStats
}

func (*anyExpression) isExpression() {}

func (e *anyExpression) stats() expressionStats {
	return e.statistics
}

func (e *anyExpression) evaluate(
	claims Claims,
) bool {
	for _, expression := range e.expressions {
		if expression.evaluate(
			claims,
		) {
			return true
		}
	}

	return false
}

type matchExpression struct {
	name     Name
	operator Operator
	value    string
	regex    *regexp.Regexp
}

func (*matchExpression) isExpression() {}

func (*matchExpression) stats() expressionStats {
	return expressionStats{
		depth: 1,
		nodes: 1,
	}
}

func (e *matchExpression) evaluate(
	claims Claims,
) bool {
	switch e.name {
	case NameSubject:
		return e.matchScalar(
			claims.Subject,
		)

	case NameIssuer:
		return e.matchScalar(
			claims.Issuer,
		)

	case NameAudience:
		return e.matchSlice(
			claims.Audience,
		)

	case NameID:
		return e.matchScalar(
			claims.ID,
		)

	case NameUsername:
		return e.matchScalar(
			claims.Username,
		)

	case NameEmail:
		return e.matchScalar(
			claims.Email,
		)

	default:
		// Name is validated during expression construction. Returning false
		// keeps evaluation fail-closed if that invariant is ever violated.
		return false
	}
}

func (e *matchExpression) matchScalar(
	actual string,
) bool {
	// An empty normalized scalar represents an absent claim and must not
	// satisfy an expression, including a regular expression that could match
	// an empty string.
	if actual == "" {
		return false
	}

	return e.matchValue(
		actual,
	)
}

func (e *matchExpression) matchSlice(
	actual []string,
) bool {
	for _, value := range actual {
		if value == "" {
			continue
		}

		if e.matchValue(
			value,
		) {
			return true
		}
	}

	return false
}

func (e *matchExpression) matchValue(
	actual string,
) bool {
	switch e.operator {
	case OperatorEqual:
		return actual == e.value

	case OperatorRegex:
		return e.regex.MatchString(
			actual,
		)

	default:
		// Operator is validated during expression construction. Returning
		// false keeps evaluation fail-closed if that invariant is violated.
		return false
	}
}

// NewMatch constructs a validated comparison against one normalized claim.
//
// OperatorEqual performs exact, case-sensitive equality.
//
// OperatorRegex compiles the supplied pattern during construction so invalid
// patterns fail before evaluation and compilation cost is paid only once.
func NewMatch(
	name Name,
	operator Operator,
	value string,
) (Expression, error) {
	if !name.isSupported() {
		return nil, fmt.Errorf(
			"%w: %q",
			ErrInvalidName,
			name,
		)
	}

	if !operator.isSupported() {
		return nil, fmt.Errorf(
			"%w: %q",
			ErrInvalidOperator,
			operator,
		)
	}

	if value == "" {
		return nil, ErrEmptyMatchValue
	}

	if len(value) > maxMatchValueBytes {
		return nil, fmt.Errorf(
			"%w: match value exceeds %d bytes",
			ErrExpressionTooComplex,
			maxMatchValueBytes,
		)
	}

	expression := &matchExpression{
		name:     name,
		operator: operator,
		value:    value,
	}

	if operator == OperatorRegex {
		compiled, err := regexp.Compile(
			value,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: %w",
				ErrInvalidRegex,
				err,
			)
		}

		expression.regex = compiled
	}

	return expression, nil
}

// NewAll constructs a logical AND expression.
//
// At least two child expressions are required. A single expression should be
// used directly instead of being wrapped in a redundant logical group.
func NewAll(
	expressions ...Expression,
) (Expression, error) {
	children, statistics, err := prepareLogicalExpression(
		expressions,
	)
	if err != nil {
		return nil, err
	}

	return &allExpression{
		expressions: children,
		statistics:  statistics,
	}, nil
}

// NewAny constructs a logical OR expression.
//
// At least two child expressions are required. A single expression should be
// used directly instead of being wrapped in a redundant logical group.
func NewAny(
	expressions ...Expression,
) (Expression, error) {
	children, statistics, err := prepareLogicalExpression(
		expressions,
	)
	if err != nil {
		return nil, err
	}

	return &anyExpression{
		expressions: children,
		statistics:  statistics,
	}, nil
}

// Evaluate evaluates a previously validated expression against normalized
// claims.
//
// A nil expression represents the absence of additional claim policy and
// therefore succeeds.
func Evaluate(
	expression Expression,
	claims Claims,
) bool {
	if expression == nil {
		return true
	}

	return expression.evaluate(
		claims,
	)
}

func prepareLogicalExpression(
	expressions []Expression,
) ([]Expression, expressionStats, error) {
	if len(expressions) < 2 {
		return nil, expressionStats{}, fmt.Errorf(
			"%w: logical expression requires at least two children",
			ErrInvalidExpression,
		)
	}

	statistics := expressionStats{
		depth: 1,
		nodes: 1,
	}

	children := make(
		[]Expression,
		len(expressions),
	)

	for index, expression := range expressions {
		if expression == nil {
			return nil, expressionStats{}, fmt.Errorf(
				"%w: child %d is nil",
				ErrInvalidExpression,
				index,
			)
		}

		childStats := expression.stats()

		statistics.nodes += childStats.nodes

		childDepth := childStats.depth + 1
		if childDepth > statistics.depth {
			statistics.depth = childDepth
		}

		if statistics.nodes > maxExpressionNodes {
			return nil, expressionStats{}, fmt.Errorf(
				"%w: expression exceeds %d nodes",
				ErrExpressionTooComplex,
				maxExpressionNodes,
			)
		}

		if statistics.depth > maxExpressionDepth {
			return nil, expressionStats{}, fmt.Errorf(
				"%w: expression exceeds depth %d",
				ErrExpressionTooComplex,
				maxExpressionDepth,
			)
		}

		children[index] = expression
	}

	return children, statistics, nil
}
