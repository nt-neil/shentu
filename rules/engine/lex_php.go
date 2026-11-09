package engine

import "strings"

var phpOps = []string{
	"<=>", "===", "!==", "**=", "...", "??=", "?->", "<<=", ">>=",
	"->", "=>", "::", "==", "!=", "<>", "<=", ">=", "&&", "||", "??", "++", "--",
	"+=", "-=", "*=", "/=", ".=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
}

// LexPHP lexes a PHP file. Text outside <?php ... ?> is skipped, "?>" ends a
// statement, and comments are dropped. Unterminated strings, heredocs and
// comments run to the end of the file.
func LexPHP(src string) []Token { return lexPHP(src, nil, false) }

func lexPHP(src string, b *budget, code bool) []Token {
	s := &scanner{src: src, line: 1, b: b}
	if !code {
		s.phpHTML()
	}
	s.php(false)
	return s.toks
}

// phpHTML skips inline HTML up to the next opening tag.
func (s *scanner) phpHTML() {
	for s.pos < len(s.src) {
		i := strings.Index(s.src[s.pos:], "<?")
		if i < 0 {
			s.advance(len(s.src) - s.pos)
			return
		}
		s.advance(i + 2)
		switch {
		case s.has("php"):
			s.pos += 3
		case s.has("="):
			s.pos++
			s.emit(Token{Kind: Ident, Text: "echo", Line: s.line})
		}
		return
	}
}

// php lexes code. With stop it returns at an unmatched "}" (the end of "{$...}").
func (s *scanner) php(stop bool) {
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
		case !stop && s.has("?>"):
			s.pos += 2
			s.emit(Token{Kind: Op, Text: ";", Line: s.line})
			s.phpHTML()
		case c == '#' && s.peek(1) == '[':
			s.phpAttribute()
		case c == '#' || s.has("//"):
			for s.pos < len(s.src) && s.src[s.pos] != '\n' && !s.has("?>") {
				s.pos++
			}
		case s.has("/*"):
			s.skipBlockComment()
		case c == '$' && isIdentStart(s.peek(1)):
			line := s.line
			s.pos++
			s.emit(Token{Kind: Var, Text: "$" + s.ident(""), Line: line})
		case isIdentStart(c):
			line := s.line
			s.emit(Token{Kind: Ident, Text: s.ident(""), Line: line})
		case isDigit(c) || c == '.' && isDigit(s.peek(1)):
			line := s.line
			s.emit(Token{Kind: Num, Text: s.number(), Line: line})
		case c == '\'':
			s.phpSingle()
		case c == '"' || c == '`':
			s.phpDouble(c)
		case s.has("<<<") && s.heredoc():
		case stop && c == '}' && depth == 0:
			return
		default:
			line := s.line
			o := s.operator(phpOps)
			switch o {
			case "{", "(", "[":
				depth++
			case "}", ")", "]":
				if depth > 0 {
					depth--
				}
			}
			s.emit(Token{Kind: Op, Text: o, Line: line})
		}
	}
}

// phpAttribute skips a #[...] attribute, which may span lines and hold strings.
func (s *scanner) phpAttribute() {
	depth := 0
	for s.pos < len(s.src) {
		switch s.src[s.pos] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				s.pos++
				return
			}
		case '\'', '"':
			q := s.src[s.pos]
			s.pos++
			for s.pos < len(s.src) && s.src[s.pos] != q {
				if s.src[s.pos] == '\\' {
					s.advance(1)
				}
				s.advance(1)
			}
		case '\n':
			s.line++
		}
		s.pos++
	}
}

func (s *scanner) phpSingle() {
	line := s.line
	s.pos++
	start := s.pos
	for s.pos < len(s.src) && s.src[s.pos] != '\'' {
		if s.src[s.pos] == '\\' {
			s.advance(1)
		}
		s.advance(1)
	}
	t := Token{Kind: Str, Text: s.src[start:min(s.pos, len(s.src))], Line: line}
	if s.pos < len(s.src) {
		s.pos++
	} else {
		t.Flags |= FlagOpen
		s.b.unterminated()
	}
	s.emit(t)
}

// phpDouble lexes "..." and `...`, both of which interpolate variables.
func (s *scanner) phpDouble(q byte) {
	line := s.line
	s.pos++
	start := s.pos
	parts := s.phpParts(start, len(s.src), q)
	t := Token{Kind: Str, Text: s.src[start:min(s.pos, len(s.src))], Line: line, Parts: parts}
	if q == '`' {
		t.Flags |= FlagShell
	}
	if s.pos < len(s.src) {
		s.pos++
	} else {
		t.Flags |= FlagOpen
		s.b.unterminated()
	}
	s.emit(t)
}

// heredoc lexes <<<ID, <<<"ID" and <<<'ID' (nowdoc, no interpolation). It returns
// false when the text after <<< is not a heredoc start.
func (s *scanner) heredoc() bool {
	i := s.pos + 3
	for i < len(s.src) && (s.src[i] == ' ' || s.src[i] == '\t') {
		i++
	}
	quote := byte(0)
	if i < len(s.src) && (s.src[i] == '\'' || s.src[i] == '"') {
		quote = s.src[i]
		i++
	}
	if i >= len(s.src) || !isIdentStart(s.src[i]) {
		return false
	}
	idStart := i
	for i < len(s.src) && isIdentChar(s.src[i]) {
		i++
	}
	id := s.src[idStart:i]
	if quote != 0 {
		if i >= len(s.src) || s.src[i] != quote {
			return false
		}
		i++
	}
	if i < len(s.src) && s.src[i] == '\r' {
		i++
	}
	if i >= len(s.src) || s.src[i] != '\n' {
		return false
	}
	bodyStart := i + 1
	bodyEnd, after := len(s.src), len(s.src)
	open := true
	for j := bodyStart; j <= len(s.src); {
		k := j
		for k < len(s.src) && (s.src[k] == ' ' || s.src[k] == '\t') {
			k++
		}
		if strings.HasPrefix(s.src[k:], id) && (k+len(id) >= len(s.src) || !isIdentChar(s.src[k+len(id)])) {
			bodyEnd, after, open = max(j-1, bodyStart), k+len(id), false
			break
		}
		nl := strings.IndexByte(s.src[j:], '\n')
		if nl < 0 {
			break
		}
		j += nl + 1
	}
	line := s.line
	s.advance(bodyStart - s.pos)
	t := Token{Kind: Str, Line: line, Text: strings.TrimSuffix(s.src[bodyStart:bodyEnd], "\r")}
	if quote != '\'' {
		t.Parts = s.phpParts(bodyStart, bodyEnd, 0)
	}
	s.advance(after - s.pos)
	if open {
		t.Flags |= FlagOpen
		s.b.unterminated()
	}
	s.emit(t)
	return true
}

// phpParts scans string content from s.pos up to limit or the closing quote q
// (0 for a heredoc) and lexes its interpolations. start is where the content begins.
func (s *scanner) phpParts(start, limit int, q byte) []Part {
	var parts []Part
	for s.pos < limit && (q == 0 || s.src[s.pos] != q) {
		c := s.src[s.pos]
		switch {
		case c == '\\':
			s.advance(min(2, limit-s.pos))
		case c == '$' && s.pos+1 < limit && isIdentStart(s.src[s.pos+1]):
			parts = append(parts, s.phpSimpleVar(start, limit))
		case c == '{' && s.pos+1 < limit && s.src[s.pos+1] == '$':
			parts = append(parts, s.phpBraced(start, limit, 1))
		case c == '$' && s.pos+1 < limit && s.src[s.pos+1] == '{':
			parts = append(parts, s.phpBraced(start, limit, 2))
		default:
			s.advance(1)
		}
	}
	return parts
}

// phpSimpleVar lexes "$name", "$name[key]" and "$name->prop" inside a string.
func (s *scanner) phpSimpleVar(start, limit int) Part {
	p := Part{Off: s.pos - start}
	s.pos++
	name := s.ident("")
	p.Toks = append(p.Toks, Token{Kind: Var, Text: "$" + name, Line: s.line})
	switch {
	case s.pos < limit && s.src[s.pos] == '[':
		end := s.pos + 1
		for end < limit && (isIdentChar(s.src[end]) || s.src[end] == '$' || s.src[end] == '-') {
			end++
		}
		if end < limit && s.src[end] == ']' && end > s.pos+1 {
			key := s.src[s.pos+1 : end]
			kt := Token{Kind: Str, Text: key, Line: s.line}
			if key[0] == '$' {
				kt.Kind = Var
			} else if isDigit(key[0]) || key[0] == '-' {
				kt.Kind = Num
			}
			p.Toks = append(p.Toks, Token{Kind: Op, Text: "[", Line: s.line}, kt, Token{Kind: Op, Text: "]", Line: s.line})
			s.pos = end + 1
		}
	case s.pos+2 < limit && s.src[s.pos] == '-' && s.src[s.pos+1] == '>' && isIdentStart(s.src[s.pos+2]):
		s.pos += 2
		p.Toks = append(p.Toks, Token{Kind: Op, Text: "->", Line: s.line}, Token{Kind: Ident, Text: s.ident(""), Line: s.line})
	}
	for range p.Toks {
		s.b.token()
	}
	return p
}

// phpBraced lexes "{$expr}" (skip 1) and "${expr}" (skip 2) inside a string.
func (s *scanner) phpBraced(start, limit, skip int) Part {
	p := Part{Off: s.pos - start}
	s.pos += skip
	if s.depth >= maxNest {
		for s.pos < limit && s.src[s.pos] != '}' {
			s.advance(1)
		}
		s.pos = min(s.pos+1, limit)
		return p
	}
	sub := &scanner{src: s.src[:limit], pos: s.pos, line: s.line, b: s.b, depth: s.depth + 1}
	sub.php(true)
	p.Toks = sub.toks
	if skip == 2 && len(p.Toks) == 1 && p.Toks[0].Kind == Ident {
		p.Toks[0].Kind, p.Toks[0].Text = Var, "$"+p.Toks[0].Text
	}
	s.pos, s.line = sub.pos, sub.line
	if s.pos < limit && s.src[s.pos] == '}' {
		s.pos++
	}
	return p
}
