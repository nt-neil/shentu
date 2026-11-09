package engine

import "strings"

var pyOps = []string{
	"**=", "//=", ">>=", "<<=", "...", "->", ":=", "**", "//", "==", "!=", "<=", ">=", "<<", ">>",
	"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "@=",
}

// LexPython lexes a Python file. Logical lines end with a Newline token, blocks
// are marked with Indent and Dedent, comments are dropped, and f-string fields
// are lexed as code. Unterminated strings end at the end of the line (triple
// quoted ones at the end of the file).
func LexPython(src string) []Token { return lexPython(src, nil) }

func lexPython(src string, b *budget) []Token {
	s := &scanner{src: src, line: 1, b: b}
	s.python(false)
	return s.toks
}

// python lexes code. In expr mode (an f-string field) it emits no Newline or
// Indent and stops at a "}", ":" or "!" outside brackets.
func (s *scanner) python(expr bool) {
	indents := []int{0}
	depth := 0
	lineStart := !expr
	for s.pos < len(s.src) && !s.b.hitLimit() {
		if lineStart && depth == 0 {
			col, i := 0, s.pos
			for i < len(s.src) && (s.src[i] == ' ' || s.src[i] == '\t' || s.src[i] == '\f') {
				if s.src[i] == '\t' {
					col = (col/8 + 1) * 8
				} else {
					col++
				}
				i++
			}
			s.pos = i
			if i >= len(s.src) {
				break
			}
			if c := s.src[i]; c == '\n' || c == '\r' || c == '#' {
				if c == '#' {
					s.skipLine()
				}
				if s.pos < len(s.src) {
					s.advance(1)
				}
				continue
			}
			lineStart = false
			if col > indents[len(indents)-1] {
				indents = append(indents, col)
				s.emit(Token{Kind: Indent, Line: s.line})
			}
			for len(indents) > 1 && col < indents[len(indents)-1] {
				indents = indents[:len(indents)-1]
				s.emit(Token{Kind: Dedent, Line: s.line})
			}
		}
		c := s.src[s.pos]
		switch {
		case c == '\n' && expr && depth == 0:
			return
		case c == '\n':
			if depth == 0 && !expr {
				s.endLine()
				lineStart = true
			}
			s.advance(1)
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			s.pos++
		case c == '#':
			s.skipLine()
		case c == '\\' && (s.peek(1) == '\n' || s.peek(1) == '\r' && s.peek(2) == '\n'):
			s.advance(2)
			if s.peek(0) == '\n' {
				s.advance(1)
			}
		case c == '\'' || c == '"':
			s.pyString("")
		case isIdentStart(c):
			line := s.line
			name := s.ident("")
			if q := s.peek(0); (q == '\'' || q == '"') && len(name) <= 2 && strings.Trim(strings.ToLower(name), "rbuft") == "" {
				s.pyString(name)
			} else {
				s.emit(Token{Kind: Ident, Text: name, Line: line})
			}
		case isDigit(c) || c == '.' && isDigit(s.peek(1)):
			line := s.line
			s.emit(Token{Kind: Num, Text: s.number(), Line: line})
		case expr && depth == 0 && (c == '}' || c == ':' && s.peek(1) != '=' || c == '!' && s.peek(1) != '='):
			return
		default:
			line := s.line
			o := s.operator(pyOps)
			switch o {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				if depth > 0 {
					depth--
				}
			}
			s.emit(Token{Kind: Op, Text: o, Line: line})
		}
	}
	if !expr {
		s.endLine()
		for len(indents) > 1 {
			indents = indents[:len(indents)-1]
			s.emit(Token{Kind: Dedent, Line: s.line})
		}
	}
}

func (s *scanner) endLine() {
	if n := len(s.toks); n > 0 && s.toks[n-1].Kind != Newline && s.toks[n-1].Kind != Indent && s.toks[n-1].Kind != Dedent {
		s.emit(Token{Kind: Newline, Line: s.line})
	}
}

// pyString lexes a string literal at s.pos with the given prefix (r, b, f, rb, ...).
func (s *scanner) pyString(prefix string) {
	line := s.line
	q := s.src[s.pos]
	quote := string(q)
	if s.has(strings.Repeat(quote, 3)) {
		quote = strings.Repeat(quote, 3)
	}
	lp := strings.ToLower(prefix)
	fmtStr := strings.ContainsAny(lp, "ft")
	s.pos += len(quote)
	start := s.pos
	var parts []Part
	for s.pos < len(s.src) {
		c := s.src[s.pos]
		if c == '\\' {
			s.advance(2)
			continue
		}
		if s.has(quote) || len(quote) == 1 && c == '\n' {
			break
		}
		if fmtStr && c == '{' {
			if s.peek(1) == '{' {
				s.pos += 2
				continue
			}
			parts = append(parts, s.pyField(start, quote))
			continue
		}
		s.advance(1)
	}
	end := min(s.pos, len(s.src))
	t := Token{Kind: Str, Text: s.src[start:end], Line: line, Parts: parts}
	if s.has(quote) {
		s.pos += len(quote)
	} else {
		t.Flags |= FlagOpen
	}
	s.emit(t)
}

// pyField lexes one f-string replacement field "{expr!r:spec}".
func (s *scanner) pyField(start int, quote string) Part {
	p := Part{Off: s.pos - start}
	s.pos++
	if s.depth < maxNest {
		sub := &scanner{src: s.src, pos: s.pos, line: s.line, b: s.b, depth: s.depth + 1}
		sub.python(true)
		p.Toks = sub.toks
		s.pos, s.line = sub.pos, sub.line
	}
	// Skip the conversion and format spec up to the field's closing brace.
	depth := 0
	for s.pos < len(s.src) {
		c := s.src[s.pos]
		if s.has(quote) || len(quote) == 1 && c == '\n' {
			return p
		}
		s.advance(1)
		if c == '{' {
			depth++
		} else if c == '}' {
			if depth == 0 {
				return p
			}
			depth--
		}
	}
	return p
}
