package parser

import (
	"errors"
	"reflect"
	"testing"
)

func TestLexer_EmptyInput(t *testing.T) {
	tokens, err := lexAll("")
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	want := []token{
		{
			kind:     tokenEOF,
			position: 0,
		},
	}

	if !reflect.DeepEqual(tokens, want) {
		t.Fatalf(
			"tokens = %#v, want %#v",
			tokens,
			want,
		)
	}
}

func TestLexer_WhitespaceOnly(t *testing.T) {
	tokens, err := lexAll(
		" \t\r\n ",
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	if len(tokens) != 1 {
		t.Fatalf(
			"token count = %d, want 1",
			len(tokens),
		)
	}

	if tokens[0].kind != tokenEOF {
		t.Fatalf(
			"token kind = %v, want EOF",
			tokens[0].kind,
		)
	}
}

func TestLexer_Match(t *testing.T) {
	tokens, err := lexAll(
		`subject == "camera-front"`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	wantKinds := []tokenKind{
		tokenIdentifier,
		tokenEqual,
		tokenString,
		tokenEOF,
	}

	assertTokenKinds(
		t,
		tokens,
		wantKinds,
	)

	if tokens[0].value != "subject" {
		t.Fatalf(
			"identifier = %q, want %q",
			tokens[0].value,
			"subject",
		)
	}

	if tokens[2].value != "camera-front" {
		t.Fatalf(
			"string = %q, want %q",
			tokens[2].value,
			"camera-front",
		)
	}
}

func TestLexer_Regex(t *testing.T) {
	tokens, err := lexAll(
		`subject ~= "^camera-[a-z]+$"`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	wantKinds := []tokenKind{
		tokenIdentifier,
		tokenRegex,
		tokenString,
		tokenEOF,
	}

	assertTokenKinds(
		t,
		tokens,
		wantKinds,
	)

	if tokens[2].value != "^camera-[a-z]+$" {
		t.Fatalf(
			"regex = %q, want %q",
			tokens[2].value,
			"^camera-[a-z]+$",
		)
	}
}

func TestLexer_LogicalOperatorsAndParentheses(t *testing.T) {
	tokens, err := lexAll(
		`(subject == "front" || subject == "back") && audience == "frigate"`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	wantKinds := []tokenKind{
		tokenLeftParenthesis,
		tokenIdentifier,
		tokenEqual,
		tokenString,
		tokenOr,
		tokenIdentifier,
		tokenEqual,
		tokenString,
		tokenRightParenthesis,
		tokenAnd,
		tokenIdentifier,
		tokenEqual,
		tokenString,
		tokenEOF,
	}

	assertTokenKinds(
		t,
		tokens,
		wantKinds,
	)
}

func TestLexer_AllowsIdentifierCharacters(t *testing.T) {
	tokens, err := lexAll(
		`custom_claim-2 == "value"`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	if tokens[0].kind != tokenIdentifier {
		t.Fatalf(
			"token kind = %v, want identifier",
			tokens[0].kind,
		)
	}

	if tokens[0].value != "custom_claim-2" {
		t.Fatalf(
			"identifier = %q, want %q",
			tokens[0].value,
			"custom_claim-2",
		)
	}
}

func TestLexer_DecodesEscapedQuote(t *testing.T) {
	tokens, err := lexAll(
		`subject == "camera-\"front\""`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	if tokens[2].value != `camera-"front"` {
		t.Fatalf(
			"value = %q, want %q",
			tokens[2].value,
			`camera-"front"`,
		)
	}
}

func TestLexer_DecodesEscapedBackslash(t *testing.T) {
	tokens, err := lexAll(
		`subject ~= "^camera\\-[0-9]+$"`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	if tokens[2].value != `^camera\-[0-9]+$` {
		t.Fatalf(
			"value = %q, want %q",
			tokens[2].value,
			`^camera\-[0-9]+$`,
		)
	}
}

func TestLexer_DecodesUnicodeEscape(t *testing.T) {
	tokens, err := lexAll(
		`subject == "\u043a\u0430\u043c\u0435\u0440\u0430"`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	if tokens[2].value != "камера" {
		t.Fatalf(
			"value = %q, want %q",
			tokens[2].value,
			"камера",
		)
	}
}

func TestLexer_AllowsRawUTF8InsideString(t *testing.T) {
	tokens, err := lexAll(
		`subject == "камера-передняя"`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	if tokens[2].value != "камера-передняя" {
		t.Fatalf(
			"value = %q, want %q",
			tokens[2].value,
			"камера-передняя",
		)
	}
}

func TestLexer_PreservesTokenPositions(t *testing.T) {
	tokens, err := lexAll(
		`  subject == "x"`,
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	if tokens[0].position != 2 {
		t.Fatalf(
			"identifier position = %d, want 2",
			tokens[0].position,
		)
	}

	if tokens[1].position != 10 {
		t.Fatalf(
			"operator position = %d, want 10",
			tokens[1].position,
		)
	}

	if tokens[2].position != 13 {
		t.Fatalf(
			"string position = %d, want 13",
			tokens[2].position,
		)
	}
}

func TestLexer_RejectsSingleEqual(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject = "camera"`,
	)
}

func TestLexer_RejectsSingleTilde(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject ~ "camera"`,
	)
}

func TestLexer_RejectsSingleAmpersand(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject == "a" & audience == "b"`,
	)
}

func TestLexer_RejectsSinglePipe(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject == "a" | audience == "b"`,
	)
}

func TestLexer_RejectsUnknownCharacter(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject == "a" @ audience == "b"`,
	)
}

func TestLexer_RejectsUnterminatedString(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject == "camera`,
	)
}

func TestLexer_RejectsTrailingEscape(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject == "camera\`,
	)
}

func TestLexer_RejectsRawNewlineInsideString(t *testing.T) {
	assertLexerSyntaxError(
		t,
		"subject == \"camera\nfront\"",
	)
}

func TestLexer_RejectsInvalidEscape(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject == "\q"`,
	)
}

func TestLexer_RejectsInvalidHexEscape(t *testing.T) {
	assertLexerSyntaxError(
		t,
		`subject == "\xZZ"`,
	)
}

func TestLexer_WhitespaceBetweenEveryToken(t *testing.T) {
	tokens, err := lexAll(
		" \n (\t subject \r == \n \"front\" \t ) \n ",
	)
	if err != nil {
		t.Fatalf(
			"lexAll() error = %v, want nil",
			err,
		)
	}

	wantKinds := []tokenKind{
		tokenLeftParenthesis,
		tokenIdentifier,
		tokenEqual,
		tokenString,
		tokenRightParenthesis,
		tokenEOF,
	}

	assertTokenKinds(
		t,
		tokens,
		wantKinds,
	)
}

func lexAll(
	value string,
) ([]token, error) {
	l := newLexer(
		value,
	)

	var tokens []token

	for {
		current, err := l.next()
		if err != nil {
			return nil, err
		}

		tokens = append(
			tokens,
			current,
		)

		if current.kind == tokenEOF {
			return tokens, nil
		}
	}
}

func assertTokenKinds(
	t *testing.T,
	tokens []token,
	want []tokenKind,
) {
	t.Helper()

	if len(tokens) != len(want) {
		t.Fatalf(
			"token count = %d, want %d: %#v",
			len(tokens),
			len(want),
			tokens,
		)
	}

	for index := range want {
		if tokens[index].kind != want[index] {
			t.Fatalf(
				"token %d kind = %v, want %v",
				index,
				tokens[index].kind,
				want[index],
			)
		}
	}
}

func assertLexerSyntaxError(
	t *testing.T,
	value string,
) {
	t.Helper()

	_, err := lexAll(
		value,
	)

	if !errors.Is(
		err,
		ErrSyntax,
	) {
		t.Fatalf(
			"lexAll(%q) error = %v, want ErrSyntax",
			value,
			err,
		)
	}
}
