// Package parser converts textual claim policies into validated claim
// expressions.
//
// The parser implements a deliberately small expression language:
//
//	claim == "value"
//	claim ~= "regular-expression"
//	expression && expression
//	expression || expression
//	(expression)
//
// Equality is exact and case-sensitive. Regular expressions use the semantics
// implemented by the claim package.
//
// Logical AND has higher precedence than logical OR. Parentheses may be used
// to override precedence explicitly.
//
// The parser does not define claim semantics itself. Claim names, comparison
// operators, expression structure, and regular expressions are validated
// through the claim package so textual policies and programmatically
// constructed policies share the same canonical invariants.
//
// The package is independent of HTTP, CLI, configuration files, and other
// external transports. Those layers are responsible only for obtaining the
// textual representation and passing it to Parse.
package parser

import (
	"fmt"

	"simple-jwt-authenticator/internal/token/claim"
)

const (
	// maxExpressionBytes bounds the amount of textual policy accepted before
	// lexical analysis begins.
	//
	// Expression-level limits such as match-value size, node count, and AST
	// depth remain enforced independently by the claim package.
	maxExpressionBytes = 16 * 1024

	// maxParenthesisDepth bounds recursive parser nesting independently of AST
	// depth.
	//
	// Parentheses do not necessarily add nodes to the resulting expression
	// tree, so relying only on claim AST limits would allow deeply nested input
	// to consume excessive call-stack space during parsing.
	maxParenthesisDepth = 64
)

// Parse converts a textual claim policy into a validated claim expression.
//
// Supported syntax:
//
//	claim == "value"
//	claim ~= "regular-expression"
//	expression && expression
//	expression || expression
//	(expression)
//
// Logical AND has higher precedence than logical OR.
//
// Empty input is invalid. Unknown claims, invalid regular expressions,
// malformed logical structures, and expression complexity violations are
// rejected through the canonical claim package constructors.
//
// Input size and parser nesting are additionally bounded before they can
// consume disproportionate parser resources.
func Parse(
	value string,
) (claim.Expression, error) {
	if len(value) > maxExpressionBytes {
		return nil, fmt.Errorf(
			"%w: maximum size is %d bytes",
			ErrExpressionTooLarge,
			maxExpressionBytes,
		)
	}

	p := expressionParser{
		lexer: newLexer(
			value,
		),
	}

	if err := p.advance(); err != nil {
		return nil, err
	}

	if p.current.kind == tokenEOF {
		return nil, syntaxError(
			p.current.position,
			"expression is empty",
		)
	}

	expression, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if p.current.kind != tokenEOF {
		return nil, syntaxError(
			p.current.position,
			"unexpected trailing input",
		)
	}

	return expression, nil
}

type expressionParser struct {
	lexer *lexer

	current token
	nesting int
}

func (p *expressionParser) advance() error {
	next, err := p.lexer.next()
	if err != nil {
		return err
	}

	p.current = next

	return nil
}

func (p *expressionParser) parseExpression() (
	claim.Expression,
	error,
) {
	return p.parseOr()
}

func (p *expressionParser) parseOr() (
	claim.Expression,
	error,
) {
	first, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	expressions := []claim.Expression{
		first,
	}

	for p.current.kind == tokenOr {
		if err := p.advance(); err != nil {
			return nil, err
		}

		next, err := p.parseAnd()
		if err != nil {
			return nil, err
		}

		expressions = append(
			expressions,
			next,
		)
	}

	if len(expressions) == 1 {
		return expressions[0], nil
	}

	expression, err := claim.NewAny(
		expressions...,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"construct OR expression: %w",
			err,
		)
	}

	return expression, nil
}

func (p *expressionParser) parseAnd() (
	claim.Expression,
	error,
) {
	first, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	expressions := []claim.Expression{
		first,
	}

	for p.current.kind == tokenAnd {
		if err := p.advance(); err != nil {
			return nil, err
		}

		next, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}

		expressions = append(
			expressions,
			next,
		)
	}

	if len(expressions) == 1 {
		return expressions[0], nil
	}

	expression, err := claim.NewAll(
		expressions...,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"construct AND expression: %w",
			err,
		)
	}

	return expression, nil
}

func (p *expressionParser) parsePrimary() (
	claim.Expression,
	error,
) {
	switch p.current.kind {
	case tokenIdentifier:
		return p.parseMatch()

	case tokenLeftParenthesis:
		return p.parseGroup()

	default:
		return nil, syntaxError(
			p.current.position,
			"expected claim comparison or '('",
		)
	}
}

func (p *expressionParser) parseGroup() (
	expression claim.Expression,
	err error,
) {
	p.nesting++
	defer func() {
		p.nesting--
	}()

	if p.nesting > maxParenthesisDepth {
		return nil, fmt.Errorf(
			"%w: parenthesis nesting exceeds %d",
			claim.ErrExpressionTooComplex,
			maxParenthesisDepth,
		)
	}

	if err := p.advance(); err != nil {
		return nil, err
	}

	if p.current.kind == tokenRightParenthesis {
		return nil, syntaxError(
			p.current.position,
			"empty parenthesized expression",
		)
	}

	expression, err = p.parseExpression()
	if err != nil {
		return nil, err
	}

	if p.current.kind != tokenRightParenthesis {
		return nil, syntaxError(
			p.current.position,
			"expected ')'",
		)
	}

	if err := p.advance(); err != nil {
		return nil, err
	}

	return expression, nil
}

func (p *expressionParser) parseMatch() (
	claim.Expression,
	error,
) {
	nameToken := p.current

	if err := p.advance(); err != nil {
		return nil, err
	}

	operator, err := p.parseOperator()
	if err != nil {
		return nil, err
	}

	if p.current.kind != tokenString {
		return nil, syntaxError(
			p.current.position,
			"expected quoted comparison value",
		)
	}

	value := p.current.value

	if err := p.advance(); err != nil {
		return nil, err
	}

	name, err := claim.ParseName(
		nameToken.value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse claim name: %w",
			err,
		)
	}

	expression, err := claim.NewMatch(
		name,
		operator,
		value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"construct claim comparison: %w",
			err,
		)
	}

	return expression, nil
}

func (p *expressionParser) parseOperator() (
	claim.Operator,
	error,
) {
	var operator claim.Operator

	switch p.current.kind {
	case tokenEqual:
		operator = claim.OperatorEqual

	case tokenRegex:
		operator = claim.OperatorRegex

	default:
		return "", syntaxError(
			p.current.position,
			"expected comparison operator",
		)
	}

	if err := p.advance(); err != nil {
		return "", err
	}

	return operator, nil
}
