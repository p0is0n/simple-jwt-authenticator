package parser

import (
	"fmt"
	"strconv"
)

type tokenKind uint8

const (
	tokenEOF tokenKind = iota
	tokenIdentifier
	tokenString
	tokenEqual
	tokenRegex
	tokenAnd
	tokenOr
	tokenLeftParenthesis
	tokenRightParenthesis
)

type token struct {
	kind     tokenKind
	value    string
	position int
}

type lexer struct {
	input  string
	offset int
}

func newLexer(
	input string,
) *lexer {
	return &lexer{
		input: input,
	}
}

func (l *lexer) next() (token, error) {
	l.skipWhitespace()

	if l.offset >= len(l.input) {
		return token{
			kind:     tokenEOF,
			position: len(l.input),
		}, nil
	}

	position := l.offset

	switch l.input[l.offset] {
	case '(':
		l.offset++

		return token{
			kind:     tokenLeftParenthesis,
			value:    "(",
			position: position,
		}, nil

	case ')':
		l.offset++

		return token{
			kind:     tokenRightParenthesis,
			value:    ")",
			position: position,
		}, nil

	case '=':
		if l.hasNext('=') {
			l.offset += 2

			return token{
				kind:     tokenEqual,
				value:    "==",
				position: position,
			}, nil
		}

		return token{}, syntaxError(
			position,
			"expected '=='",
		)

	case '~':
		if l.hasNext('=') {
			l.offset += 2

			return token{
				kind:     tokenRegex,
				value:    "~=",
				position: position,
			}, nil
		}

		return token{}, syntaxError(
			position,
			"expected '~='",
		)

	case '&':
		if l.hasNext('&') {
			l.offset += 2

			return token{
				kind:     tokenAnd,
				value:    "&&",
				position: position,
			}, nil
		}

		return token{}, syntaxError(
			position,
			"expected '&&'",
		)

	case '|':
		if l.hasNext('|') {
			l.offset += 2

			return token{
				kind:     tokenOr,
				value:    "||",
				position: position,
			}, nil
		}

		return token{}, syntaxError(
			position,
			"expected '||'",
		)

	case '"':
		return l.scanString()

	default:
		if isIdentifierStart(
			l.input[l.offset],
		) {
			return l.scanIdentifier(), nil
		}

		return token{}, syntaxError(
			position,
			"unexpected character",
		)
	}
}

func (l *lexer) scanIdentifier() token {
	position := l.offset

	l.offset++

	for l.offset < len(l.input) &&
		isIdentifierContinue(
			l.input[l.offset],
		) {
		l.offset++
	}

	return token{
		kind:     tokenIdentifier,
		value:    l.input[position:l.offset],
		position: position,
	}
}

func (l *lexer) scanString() (token, error) {
	position := l.offset

	// Consume the opening quote.
	l.offset++

	for l.offset < len(l.input) {
		switch l.input[l.offset] {
		case '"':
			l.offset++

			raw := l.input[position:l.offset]

			value, err := strconv.Unquote(
				raw,
			)
			if err != nil {
				return token{}, syntaxError(
					position,
					"invalid quoted string",
				)
			}

			return token{
				kind:     tokenString,
				value:    value,
				position: position,
			}, nil

		case '\\':
			l.offset++

			if l.offset >= len(l.input) {
				return token{}, syntaxError(
					position,
					"unterminated quoted string",
				)
			}

			// Skip the escaped byte. strconv.Unquote performs the canonical
			// validation of the complete escape sequence after the closing
			// quote is found.
			l.offset++

		case '\n', '\r':
			return token{}, syntaxError(
				position,
				"newline in quoted string",
			)

		default:
			l.offset++
		}
	}

	return token{}, syntaxError(
		position,
		"unterminated quoted string",
	)
}

func (l *lexer) skipWhitespace() {
	for l.offset < len(l.input) {
		switch l.input[l.offset] {
		case ' ', '\t', '\n', '\r':
			l.offset++

		default:
			return
		}
	}
}

func (l *lexer) hasNext(
	expected byte,
) bool {
	return l.offset+1 < len(l.input) &&
		l.input[l.offset+1] == expected
}

func isIdentifierStart(
	value byte,
) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value == '_'
}

func isIdentifierContinue(
	value byte,
) bool {
	return isIdentifierStart(
		value,
	) ||
		value >= '0' && value <= '9' ||
		value == '-'
}

func syntaxError(
	position int,
	message string,
) error {
	return fmt.Errorf(
		"%w at byte %d: %s",
		ErrSyntax,
		position,
		message,
	)
}
