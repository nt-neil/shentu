package engine

import "strings"

var jsOps = []string{
	">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
	"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--",
	"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
}

// regexAfter are keywords after which "/" starts a regular expression, not a division.
var regexAfter = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true, "new": true, "delete": true,
	"void": true, "throw": true, "case": true, "do": true, "else": true, "yield": true, "await": true,
}

// ctlWords are the statements whose header in parentheses is followed by a statement.
var ctlWords = map[string]bool{"if": true, "while": true, "for": true, "with": true}

// LexJS lexes a JavaScript file. Comments are dropped, template literal fields
// ${...} are lexed as code, regular expression literals become Str tokens with
// FlagRegex, and each token records whether it starts a line (for statement
// ends without semicolons). Unterminated strings end at the end of the line.
func LexJS(src string) []Token { return lexJS(src, nil) }

func lexJS(src string, b *budget) []Token {
	s := &scanner{src: src, line: 1, b: b}
	if s.has("#!") {
		s.skipLine()
	}
	s.js(false)
	return s.toks
}

// js lexes code. With stop it returns at an unmatched "}" (the end of "${...}").
func (s *scanner) js(stop bool) {
	depth := 0
	for s.pos < len(s.src) && !s.b.hitLimit() {
		c := s.src[s.pos]
		switch {
		case c == '\n':
			s.line++
			s.pos++
			s.nl = true
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			s.pos++
		case s.has("//"):
			s.skipLine()
		case s.has("/*"):
			s.skipBlockComment()
		case c == '\'' || c == '"':
			s.jsQuoted(c)
		case c == '`':
			s.jsTemplate()
		case c == '/' && s.regexAllowed():
			s.jsRegex()
		case isIdentStart(c) || c == '$' || (c == '#' || c == '@') && isIdentStart(s.peek(1)):
			// A decorator name (@Body) is one token, so a rule can name it as a source.
			line := s.line
			start := s.pos
			s.pos++
			s.ident("$")
			s.emit(Token{Kind: Ident, Text: s.src[start:s.pos], Line: line})
		case isDigit(c) || c == '.' && isDigit(s.peek(1)):
			line := s.line
			s.emit(Token{Kind: Num, Text: s.number(), Line: line})
		case stop && c == '}' && depth == 0:
			return
		default:
			line := s.line
			var o string
			if s.has("?.") && isDigit(s.peek(2)) {
				o = "?"
				s.pos++
			} else {
				o = s.operator(jsOps)
			}
			switch o {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				if depth > 0 {
					depth--
				}
			}
			switch o {
			case "(":
				n := len(s.toks)
				// o.if(x) is a method call, not an if header.
				s.ctl = append(s.ctl, n > 0 && s.toks[n-1].Kind == Ident && ctlWords[s.toks[n-1].Text] &&
					!(n > 1 && memberOp(false, s.toks[n-2])))
			case ")":
				s.afterCtl = false
				if n := len(s.ctl); n > 0 {
					s.afterCtl, s.ctl = s.ctl[n-1], s.ctl[:n-1]
				}
			}
			s.emit(Token{Kind: Op, Text: o, Line: line})
		}
	}
}

func (s *scanner) regexAllowed() bool {
	if len(s.toks) == 0 {
		return true
	}
	t := s.toks[len(s.toks)-1]
	switch t.Kind {
	case Op:
		if t.Text == ")" {
			return s.afterCtl // if (x) /re/.test(s): a statement starts after the header
		}
		if s.ts && t.Text == "!" && t.Flags&FlagNL == 0 && len(s.toks) > 1 {
			// x! / 2: a non-null assertion ends an operand.
			switch p := s.toks[len(s.toks)-2]; p.Kind {
			case Ident:
				if !regexAfter[p.Text] {
					return false
				}
			case Num, Str:
				return false
			case Op:
				if p.Text == "]" || p.Text == ")" && !s.afterCtl {
					return false
				}
			}
		}
		return t.Text != "]" && t.Text != "}" && t.Text != "++" && t.Text != "--"
	case Ident:
		return regexAfter[t.Text]
	}
	return false
}

func (s *scanner) jsQuoted(q byte) {
	line := s.line
	s.pos++
	start := s.pos
	for s.pos < len(s.src) && s.src[s.pos] != q && s.src[s.pos] != '\n' {
		if s.src[s.pos] == '\\' {
			s.advance(1)
		}
		s.advance(1)
	}
	end := min(s.pos, len(s.src))
	t := Token{Kind: Str, Text: s.src[start:end], Line: line}
	if s.pos < len(s.src) && s.src[s.pos] == q {
		s.pos++
	} else {
		t.Flags |= FlagOpen
	}
	s.emit(t)
}

func (s *scanner) jsTemplate() {
	line := s.line
	s.pos++
	start := s.pos
	var parts []Part
	for s.pos < len(s.src) && s.src[s.pos] != '`' {
		switch {
		case s.src[s.pos] == '\\':
			s.advance(2)
		case s.has("${"):
			p := Part{Off: s.pos - start}
			s.pos += 2
			if s.depth < maxNest {
				sub := &scanner{src: s.src, pos: s.pos, line: s.line, b: s.b, depth: s.depth + 1, ts: s.ts}
				sub.js(true)
				p.Toks = sub.toks
				s.pos, s.line = sub.pos, sub.line
			} else {
				for s.pos < len(s.src) && s.src[s.pos] != '}' {
					s.advance(1)
				}
			}
			if s.pos < len(s.src) && s.src[s.pos] == '}' {
				s.pos++
			}
			parts = append(parts, p)
		default:
			s.advance(1)
		}
	}
	end := min(s.pos, len(s.src))
	t := Token{Kind: Str, Text: s.src[start:end], Line: line, Parts: parts}
	if s.pos < len(s.src) {
		s.pos++
	} else {
		t.Flags |= FlagOpen
		s.b.unterminated()
	}
	s.emit(t)
}

func (s *scanner) jsRegex() {
	line := s.line
	s.pos++
	start := s.pos
	class := false
	for s.pos < len(s.src) && s.src[s.pos] != '\n' {
		c := s.src[s.pos]
		if c == '\\' {
			s.pos++
			if s.pos < len(s.src) && s.src[s.pos] == '\n' {
				break
			}
		} else if c == '[' {
			class = true
		} else if c == ']' {
			class = false
		} else if c == '/' && !class {
			break
		}
		s.pos++
	}
	end := min(s.pos, len(s.src))
	t := Token{Kind: Str, Flags: FlagRegex, Text: s.src[start:end], Line: line}
	if s.pos < len(s.src) && s.src[s.pos] == '/' {
		s.pos++
		if strings.Contains(s.ident(""), "m") {
			t.Flags |= FlagMultiline
		}
	} else {
		t.Flags |= FlagOpen
	}
	s.emit(t)
}
