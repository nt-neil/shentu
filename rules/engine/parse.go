package engine

// The parser turns tokens into a light statement tree: simple statements, if/else,
// loops, blocks and function bodies. It is not a grammar; it only finds what the
// analysis needs: statement ends, conditions, loop headers and function scopes
// (braces for PHP and JavaScript, indentation for Python). Function literals inside
// an expression (closures, arrow functions) are taken out and left as a Func token.

type stmtKind uint8

const (
	sSimple stmtKind = iota
	sIf
	sLoop
	sBlock
	sFunc
	sWith
)

type stmt struct {
	kind   stmtKind
	toks   []Token // simple: the statement; if/while: condition; loop: header; with: items; block: switch subject
	funcs  []*fn   // function literals referenced by Func tokens in toks
	body   []*stmt
	els    []*stmt
	loop   string // "for" (init; cond; step), "each" (PHP foreach), "in" (for-in/of, Python for), "while"
	alt    bool   // block: an except/catch/else path that may not run
	noexit bool   // block: a try body, whose early exit does not end the code after it
	fn     *fn
}

type fn struct {
	params []Token
	body   []*stmt
	fresh  bool // does not see the enclosing scope (PHP named functions and methods)
}

func parse(lang string, toks []Token, b *budget) []*stmt {
	if lang == "python" {
		p := &pyParser{t: toks, b: b}
		return p.block()
	}
	p := &braceParser{t: toks, php: lang == "php", b: b}
	return p.block(false)
}

func isOpen(t Token) bool  { return t.Kind == Op && (t.Text == "(" || t.Text == "[" || t.Text == "{") }
func isClose(t Token) bool { return t.Kind == Op && (t.Text == ")" || t.Text == "]" || t.Text == "}") }

// ---- PHP and JavaScript ----

type braceParser struct {
	t     []Token
	i     int
	php   bool
	b     *budget
	depth int
}

func (p *braceParser) at(text string) bool     { return p.i < len(p.t) && p.t[p.i].op(text) }
func (p *braceParser) atWord(text string) bool { return p.i < len(p.t) && p.t[p.i].word(text) }
func (p *braceParser) skip(text string) {
	if p.at(text) {
		p.i++
	}
}

// block parses statements up to the closing "}" (consumed) when inBraces, or up to
// one of the PHP alternative-syntax words in ends (not consumed), or the end.
func (p *braceParser) block(inBraces bool, ends ...string) []*stmt {
	var out []*stmt
	for p.i < len(p.t) && p.b.step() {
		t := p.t[p.i]
		if t.op("}") {
			p.i++
			if inBraces {
				return out
			}
			continue
		}
		if t.Kind == Ident && len(ends) > 0 && contains(ends, t.Text) {
			return out
		}
		start := p.i
		if s := p.statement(); s != nil {
			out = append(out, s)
		}
		if p.i == start {
			p.i++
		}
	}
	return out
}

var phpModifiers = map[string]bool{"public": true, "private": true, "protected": true, "static": true,
	"abstract": true, "final": true, "readonly": true}

func (p *braceParser) statement() *stmt {
	t := p.t[p.i]
	if p.depth > maxNest {
		return p.simple()
	}
	switch {
	case t.op(";"):
		p.i++
		return nil
	case t.op("{"):
		p.i++
		return &stmt{kind: sBlock, body: p.nested(func() []*stmt { return p.block(true) })}
	case t.Kind != Ident:
		return p.simple()
	}
	next := func(k int) Token {
		if p.i+k < len(p.t) {
			return p.t[p.i+k]
		}
		return Token{}
	}
	switch t.Text {
	case "if", "elseif":
		return p.ifStmt()
	case "for", "foreach", "while":
		return p.loopStmt()
	case "do":
		p.i++
		body := p.bodyStmt()
		s := &stmt{kind: sLoop, loop: "while", body: body}
		if p.atWord("while") {
			p.i++
			s.toks, s.funcs = p.group()
		}
		return s
	case "switch":
		p.i++
		s := &stmt{kind: sBlock}
		s.toks, s.funcs = p.group()
		if p.at("{") {
			p.i++
			s.body = p.nested(func() []*stmt { return p.block(true) })
		} else if p.php && p.at(":") {
			p.i++
			s.body = p.nested(func() []*stmt { return p.block(false, "endswitch") })
			p.i++
		}
		return s
	case "case":
		for p.i < len(p.t) && !p.t[p.i].op(":") && !p.t[p.i].op(";") && !p.t[p.i].op("}") {
			p.i++
		}
		p.skip(":")
		return nil
	case "default":
		if next(1).op(":") {
			p.i += 2
			return nil
		}
	case "try":
		p.i++
		parts := []*stmt{{kind: sBlock, noexit: true, body: p.bodyStmt()}}
		for p.atWord("catch") || p.atWord("except") {
			p.i++
			if p.at("(") {
				p.group()
			}
			parts = append(parts, &stmt{kind: sBlock, alt: true, body: p.bodyStmt()})
		}
		if p.atWord("finally") {
			p.i++
			parts = append(parts, &stmt{kind: sBlock, body: p.bodyStmt()})
		}
		return &stmt{kind: sBlock, body: parts}
	case "function":
		if n := next(1); n.Kind == Ident || n.op("&") && next(2).Kind == Ident || n.op("*") {
			return p.funcDecl()
		}
	case "async":
		if next(1).word("function") {
			p.i++
			return p.statement()
		}
	case "export":
		p.i++
		if p.atWord("default") {
			p.i++
		}
		if p.i < len(p.t) {
			return p.statement()
		}
		return nil
	case "class", "interface", "trait", "enum":
		if t.Text == "enum" && !p.php {
			break
		}
		return p.classStmt()
	case "abstract", "final", "readonly":
		if p.php && (next(1).word("class") || next(2).word("class")) {
			p.i++
			return p.statement()
		}
	case "namespace":
		if p.php {
			j := p.i + 1
			for j < len(p.t) && (p.t[j].Kind == Ident || p.t[j].op("\\")) {
				j++
			}
			if j < len(p.t) && p.t[j].op("{") {
				p.i = j + 1
				return &stmt{kind: sBlock, body: p.nested(func() []*stmt { return p.block(true) })}
			}
		}
	}
	if p.php && phpModifiers[t.Text] {
		j := p.i
		for j < len(p.t) && p.t[j].Kind == Ident && phpModifiers[p.t[j].Text] {
			j++
		}
		if j < len(p.t) && p.t[j].word("function") {
			p.i = j
			return p.funcDecl()
		}
	}
	return p.simple()
}

func (p *braceParser) nested(f func() []*stmt) []*stmt {
	p.depth++
	defer func() { p.depth-- }()
	return f()
}

// bodyStmt parses the body of if/for/while: a braced block or one statement.
func (p *braceParser) bodyStmt() []*stmt {
	if p.i >= len(p.t) {
		return nil
	}
	if p.at("{") {
		p.i++
		return p.nested(func() []*stmt { return p.block(true) })
	}
	p.depth++
	defer func() { p.depth-- }()
	if s := p.statement(); s != nil {
		return []*stmt{s}
	}
	return nil
}

func (p *braceParser) ifStmt() *stmt {
	p.i++
	s := &stmt{kind: sIf}
	s.toks, s.funcs = p.group()
	if p.php && p.at(":") {
		p.i++
		s.body = p.nested(func() []*stmt { return p.block(false, "elseif", "else", "endif") })
		switch {
		case p.atWord("elseif"):
			s.els = []*stmt{p.ifStmt()}
		case p.atWord("else"):
			p.i++
			if p.atWord("if") {
				s.els = []*stmt{p.ifStmt()}
				break
			}
			p.skip(":")
			s.els = p.nested(func() []*stmt { return p.block(false, "endif") })
			fallthrough
		default:
			if p.atWord("endif") {
				p.i++
				p.skip(";")
			}
		}
		return s
	}
	s.body = p.bodyStmt()
	switch {
	case p.atWord("else"):
		p.i++
		if p.atWord("if") {
			s.els = []*stmt{p.ifStmt()}
		} else {
			s.els = p.bodyStmt()
		}
	case p.php && p.atWord("elseif"):
		s.els = []*stmt{p.ifStmt()}
	}
	return s
}

func (p *braceParser) loopStmt() *stmt {
	kw := p.t[p.i].Text
	p.i++
	if p.atWord("await") {
		p.i++
	}
	s := &stmt{kind: sLoop, loop: map[string]string{"for": "for", "foreach": "each", "while": "while"}[kw]}
	s.toks, s.funcs = p.group()
	if kw == "for" && len(splitTop(s.toks, isSemi)) < 2 {
		s.loop = "in"
	}
	if p.php && p.at(":") {
		p.i++
		s.body = p.nested(func() []*stmt { return p.block(false, "end"+kw) })
		if p.atWord("end" + kw) {
			p.i++
			p.skip(";")
		}
		return s
	}
	s.body = p.bodyStmt()
	return s
}

// funcDecl parses a named function or method at the "function" keyword.
func (p *braceParser) funcDecl() *stmt {
	p.i++
	for p.at("&") || p.at("*") || p.i < len(p.t) && p.t[p.i].Kind == Ident && !p.at("(") {
		p.i++
		if p.i < len(p.t) && p.t[p.i].op("(") {
			break
		}
	}
	f := p.funcRest(p.php)
	if f == nil {
		return nil
	}
	return &stmt{kind: sFunc, fn: f}
}

// funcRest parses "(params) [use (...)] [: type] { body }" at the "(".
func (p *braceParser) funcRest(fresh bool) *fn {
	if !p.at("(") {
		return nil
	}
	params, _ := p.group()
	if p.atWord("use") {
		p.i++
		p.group()
	}
	if p.at(":") {
		p.i++
		for p.i < len(p.t) && (p.t[p.i].Kind == Ident || p.at("?") || p.at("|") || p.at("&") || p.at("\\") || p.at("(") || p.at(")")) {
			p.i++
		}
	}
	if !p.at("{") {
		p.skip(";")
		return &fn{params: params, fresh: fresh}
	}
	p.i++
	return &fn{params: params, fresh: fresh, body: p.nested(func() []*stmt { return p.block(true) })}
}

func (p *braceParser) classStmt() *stmt {
	p.i++
	depth := 0
	for p.i < len(p.t) {
		t := p.t[p.i]
		if depth == 0 && (t.op("{") || t.op(";")) {
			break
		}
		if isOpen(t) {
			depth++
		} else if isClose(t) {
			depth--
		}
		p.i++
	}
	if !p.at("{") {
		p.skip(";")
		return nil
	}
	p.i++
	if p.php {
		return &stmt{kind: sBlock, body: p.nested(func() []*stmt { return p.block(true) })}
	}
	return &stmt{kind: sBlock, body: p.nested(p.classBody)}
}

// classBody parses JavaScript class members up to the closing "}".
func (p *braceParser) classBody() []*stmt {
	var out []*stmt
	for p.i < len(p.t) && p.b.step() {
		if p.at("}") {
			p.i++
			return out
		}
		if p.at(";") {
			p.i++
			continue
		}
		start := p.i
		j := p.i
		for j < len(p.t) && (p.t[j].word("static") || p.t[j].word("async") || p.t[j].word("get") || p.t[j].word("set") || p.t[j].op("*")) &&
			j+1 < len(p.t) && !p.t[j+1].op("(") && !p.t[j+1].op("=") {
			j++
		}
		if j < len(p.t) && p.t[j].op("{") {
			p.i = j + 1
			out = append(out, &stmt{kind: sBlock, body: p.nested(func() []*stmt { return p.block(true) })})
			continue
		}
		if j < len(p.t) && p.t[j].op("[") {
			j = closeOf(p.t, j)
		}
		if j+1 < len(p.t) && p.t[j+1].op("(") {
			p.i = j + 1
			if f := p.funcRest(false); f != nil {
				out = append(out, &stmt{kind: sFunc, fn: f})
			}
		} else if s := p.simple(); s != nil {
			out = append(out, s)
		}
		if p.i == start {
			p.i++
		}
	}
	return out
}

// group reads a parenthesised group at p.i and returns its inner tokens.
func (p *braceParser) group() ([]Token, []*fn) {
	if !p.at("(") {
		return nil, nil
	}
	p.i++
	return p.collect(endGroup)
}

func (p *braceParser) simple() *stmt {
	toks, funcs := p.collect(endStmt)
	if len(toks) == 0 && len(funcs) == 0 {
		return nil
	}
	return &stmt{kind: sSimple, toks: toks, funcs: funcs}
}

const (
	endStmt  = iota // ";" (consumed), an unmatched "}" or a statement-ending line break
	endGroup        // the ")" closing the group (consumed)
	endArrow        // a concise arrow body: "," ")" "]" "}" ";" or a line break
)

// collect gathers tokens up to the end given by mode, taking function literals out.
func (p *braceParser) collect(mode int) ([]Token, []*fn) {
	var out []Token
	var funcs []*fn
	depth := 0
	for p.i < len(p.t) && p.b.step() {
		t := p.t[p.i]
		if depth == 0 {
			switch {
			case mode == endStmt && t.op(";"):
				p.i++
				return out, funcs
			case mode == endStmt && t.op("}"):
				return out, funcs
			case mode == endGroup && t.op(")"):
				p.i++
				return out, funcs
			case mode == endArrow && (t.op(",") || t.op(";") || isClose(t)):
				return out, funcs
			case mode != endGroup && !p.php && t.Flags&FlagNL != 0 && len(out) > 0 && endsExpr(out[len(out)-1]) && !continuesExpr(t):
				return out, funcs
			}
		}
		if f, ok := p.funcLiteral(&out); ok {
			funcs = append(funcs, f)
			out = append(out, Token{Kind: Func, Fn: len(funcs) - 1, Line: t.Line})
			continue
		}
		if isOpen(t) {
			depth++
		} else if isClose(t) && depth > 0 {
			depth--
		}
		out = append(out, t)
		p.i++
	}
	return out, funcs
}

var notExprEnd = map[string]bool{"typeof": true, "instanceof": true, "in": true, "of": true, "new": true, "delete": true,
	"void": true, "await": true, "yield": true, "else": true, "extends": true, "return": true, "throw": true}

func endsExpr(t Token) bool {
	switch t.Kind {
	case Ident:
		return !notExprEnd[t.Text]
	case Num, Str, Func, Var:
		return true
	case Op:
		return t.Text == ")" || t.Text == "]" || t.Text == "}" || t.Text == "++" || t.Text == "--"
	}
	return false
}

func continuesExpr(t Token) bool {
	switch t.Kind {
	case Op:
		switch t.Text {
		case "{", "}", ";", "++", "--", "!", "~", "...":
			return false
		}
		return true
	case Ident:
		return t.Text == "instanceof" || t.Text == "in" || t.Text == "of"
	}
	return false
}

// funcLiteral recognises a function literal at p.i, parses it and returns it. For
// a JavaScript arrow function the parameters were already collected into *out and
// are removed from it.
func (p *braceParser) funcLiteral(out *[]Token) (*fn, bool) {
	t := p.t[p.i]
	at := func(k int) Token {
		if p.i+k < len(p.t) {
			return p.t[p.i+k]
		}
		return Token{}
	}
	if p.depth > maxNest {
		return nil, false
	}
	switch {
	case t.word("function"):
		k := 1
		for at(k).op("&") || at(k).op("*") || at(k).Kind == Ident && at(k+1).op("(") {
			k++
		}
		if !at(k).op("(") {
			return nil, false
		}
		p.i += k
		return p.funcRest(false), true
	case p.php && t.word("fn") && at(1).op("("):
		p.i++
		params, _ := p.group()
		for p.i < len(p.t) && !p.at("=>") && (p.t[p.i].Kind == Ident || p.at(":") || p.at("?") || p.at("|") || p.at("\\")) {
			p.i++
		}
		if !p.at("=>") {
			return &fn{params: params}, true
		}
		p.i++
		return &fn{params: params, body: p.arrowBody()}, true
	case !p.php && t.op("=>"):
		o := *out
		var params []Token
		switch n := len(o); {
		case n > 0 && o[n-1].Kind == Ident:
			params, o = o[n-1:], o[:n-1]
		case n > 0 && o[n-1].op(")"):
			open := openOf(o, n-1)
			if !o[open].op("(") {
				return nil, false
			}
			params, o = o[open+1:n-1], o[:open]
		default:
			return nil, false
		}
		if n := len(o); n > 0 && o[n-1].word("async") {
			o = o[:n-1]
		}
		*out = o
		p.i++
		if p.at("{") {
			p.i++
			return &fn{params: params, body: p.nested(func() []*stmt { return p.block(true) })}, true
		}
		return &fn{params: params, body: p.arrowBody()}, true
	case !p.php && (t.Kind == Ident || t.Kind == Str || t.Kind == Num) && at(1).op("("):
		// Method shorthand in an object literal: { name(params) { ... } }.
		o := *out
		n := len(o)
		for n > 0 && (o[n-1].word("async") || o[n-1].word("get") || o[n-1].word("set") || o[n-1].op("*")) {
			n--
		}
		if n == 0 || !(o[n-1].op("{") || o[n-1].op(",")) {
			return nil, false
		}
		end := closeOf(p.t, p.i+1)
		if end+1 >= len(p.t) || !p.t[end+1].op("{") {
			return nil, false
		}
		*out = o[:n]
		p.i++
		return p.funcRest(false), true
	}
	return nil, false
}

// arrowBody parses the expression body of an arrow function as a return statement.
func (p *braceParser) arrowBody() []*stmt {
	line := 0
	if p.i < len(p.t) {
		line = p.t[p.i].Line
	}
	toks, funcs := p.nestedCollect(endArrow)
	if len(toks) == 0 {
		return nil
	}
	return []*stmt{{kind: sSimple, toks: append([]Token{{Kind: Ident, Text: "return", Line: line}}, toks...), funcs: funcs}}
}

func (p *braceParser) nestedCollect(mode int) ([]Token, []*fn) {
	p.depth++
	defer func() { p.depth-- }()
	return p.collect(mode)
}

// ---- Python ----

type pyParser struct {
	t     []Token
	i     int
	b     *budget
	depth int
}

var pyCompound = map[string]bool{"if": true, "elif": true, "else": true, "for": true, "while": true, "with": true,
	"try": true, "except": true, "finally": true, "def": true, "class": true, "match": true, "case": true}

func (p *pyParser) block() []*stmt {
	var out []*stmt
	for p.i < len(p.t) && p.b.step() {
		switch p.t[p.i].Kind {
		case Dedent:
			p.i++
			return out
		case Newline:
			p.i++
			continue
		case Indent:
			p.i++
			out = append(out, &stmt{kind: sBlock, body: p.nested()})
			continue
		}
		start := p.i
		out = append(out, p.statement()...)
		if p.i == start {
			p.i++
		}
	}
	return out
}

func (p *pyParser) nested() []*stmt {
	if p.depth > maxNest {
		// Too deep: read the rest of this block flat.
		var out []*stmt
		for p.i < len(p.t) && p.t[p.i].Kind != Dedent && p.b.step() {
			start := p.i
			if k := p.t[p.i].Kind; k == Newline || k == Indent {
				p.i++
				continue
			}
			out = append(out, p.simpleLine()...)
			if p.i == start {
				p.i++
			}
		}
		if p.i < len(p.t) {
			p.i++
		}
		return out
	}
	p.depth++
	defer func() { p.depth-- }()
	return p.block()
}

// line returns the tokens of the logical line at p.i, without moving.
func (p *pyParser) line() []Token {
	end := p.i
	for end < len(p.t) && p.t[end].Kind != Newline && p.t[end].Kind != Indent && p.t[end].Kind != Dedent {
		end++
	}
	return p.t[p.i:end]
}

func (p *pyParser) simpleLine() []*stmt {
	l := p.line()
	p.i += len(l)
	return simpleStmts(l)
}

func simpleStmts(l []Token) []*stmt {
	var out []*stmt
	for _, part := range splitTop(l, isSemi) {
		if len(part) > 0 {
			out = append(out, &stmt{kind: sSimple, toks: part})
		}
	}
	return out
}

func (p *pyParser) statement() []*stmt {
	l := p.line()
	if len(l) == 0 {
		return nil
	}
	kw := l[0]
	if kw.word("async") && len(l) > 1 {
		kw = l[1]
		l = l[1:]
		p.i++
	}
	colon := -1
	if kw.Kind == Ident && pyCompound[kw.Text] {
		depth := 0
		for k, t := range l {
			if isOpen(t) {
				depth++
			} else if isClose(t) {
				depth--
			} else if depth == 0 && t.op(":") {
				colon = k
				break
			}
		}
	}
	if colon < 0 || (kw.Text == "match" || kw.Text == "case") && !(colon == len(l)-1 && p.i+len(l)+1 < len(p.t) && p.t[p.i+len(l)+1].Kind == Indent) {
		return p.simpleLine()
	}
	header := l[1:colon]
	inline := l[colon+1:]
	p.i += len(l)
	var body []*stmt
	if len(inline) > 0 {
		body = simpleStmts(inline)
	} else {
		if p.i < len(p.t) && p.t[p.i].Kind == Newline {
			p.i++
		}
		if p.i < len(p.t) && p.t[p.i].Kind == Indent {
			p.i++
			body = p.nested()
		}
	}
	switch kw.Text {
	case "if", "elif":
		s := &stmt{kind: sIf, toks: header, body: body}
		for p.i < len(p.t) && p.t[p.i].Kind == Newline {
			p.i++
		}
		if p.i < len(p.t) {
			switch {
			case p.t[p.i].word("elif"):
				s.els = p.statement()
			case p.t[p.i].word("else"):
				if e := p.statement(); len(e) == 1 {
					s.els = e[0].body
				}
			}
		}
		return []*stmt{s}
	case "for":
		return []*stmt{{kind: sLoop, loop: "in", toks: header, body: body}}
	case "while":
		return []*stmt{{kind: sLoop, loop: "while", toks: header, body: body}}
	case "with":
		return []*stmt{{kind: sWith, toks: header, body: body}}
	case "def":
		f := &fn{body: body}
		if len(header) > 1 && header[1].op("(") {
			f.params = header[2:max(2, closeOf(header, 1))]
		}
		return []*stmt{{kind: sFunc, fn: f}}
	case "except", "else", "case":
		return []*stmt{{kind: sBlock, alt: true, body: body}}
	case "try":
		return []*stmt{{kind: sBlock, noexit: true, body: body}}
	}
	return []*stmt{{kind: sBlock, toks: header, body: body}}
}

// ---- token helpers shared with the analysis ----

func isSemi(t Token) bool  { return t.op(";") }
func isComma(t Token) bool { return t.op(",") }

// splitTop splits toks at the tokens matching sep outside brackets.
func splitTop(toks []Token, sep func(Token) bool) [][]Token {
	var out [][]Token
	depth, start := 0, 0
	for i, t := range toks {
		switch {
		case isOpen(t):
			depth++
		case isClose(t):
			if depth > 0 {
				depth--
			}
		case depth == 0 && sep(t):
			out = append(out, toks[start:i])
			start = i + 1
		}
	}
	return append(out, toks[start:])
}

// indexTop returns the first index of a token matching f outside brackets, or -1.
func indexTop(toks []Token, from int, f func(Token) bool) int {
	depth := 0
	for i := from; i < len(toks); i++ {
		t := toks[i]
		switch {
		case isOpen(t):
			depth++
		case isClose(t):
			if depth > 0 {
				depth--
			}
		case depth == 0 && f(t):
			return i
		}
	}
	return -1
}

// closeOf returns the index of the bracket closing the one at i (or the last index).
func closeOf(toks []Token, i int) int {
	depth := 0
	for j := i; j < len(toks); j++ {
		if isOpen(toks[j]) {
			depth++
		} else if isClose(toks[j]) {
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return len(toks) - 1
}

// inside returns the tokens between the bracket at i and its closing bracket at c
// (nothing when the bracket is never closed and is the last token).
func inside(t []Token, i, c int) []Token {
	if c <= i {
		return nil
	}
	return t[i+1 : c]
}

// openOf returns the index of the bracket opening the one closing at i (or 0).
func openOf(toks []Token, i int) int {
	depth := 0
	for j := i; j >= 0; j-- {
		if isClose(toks[j]) {
			depth++
		} else if isOpen(toks[j]) {
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return 0
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
