package engine

import "strings"

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
	sTry    // body, then handlers (catch/except) from any point of it, then els (finally)
	sSwitch // cases, each a branch; falls through until break
)

type stmt struct {
	kind  stmtKind
	toks  []Token // simple: the statement; if/while: condition; loop: header; with: items; block: switch subject
	funcs []*fn   // function literals referenced by Func tokens in toks
	body  []*stmt
	els   []*stmt
	loop  string // "for" (init; cond; step), "each" (PHP foreach), "in" (for-in/of, Python for), "while"
	alt   bool   // block: an else path (for/while else, match case) that may not run
	fn    *fn

	handlers   [][]*stmt // try: catch / except bodies
	orelse     []*stmt   // try: Python else
	cases      [][]*stmt // switch
	hasDefault bool      // switch
}

type fn struct {
	params []Token
	body   []*stmt
	fresh  bool     // does not see the enclosing scope (PHP named functions and methods)
	name   string   // declared name ("" for a literal); see collectFuncs for assigned literals
	method bool     // declared in a class body
	public bool     // part of the public API: not private, protected, _name or #name
	class  string   // the class a method is declared in
	parent string   // that class's parent (extends), as written
	traits []string // PHP traits the class uses (use T;) before the method
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
	t       []Token
	i       int
	php     bool
	b       *budget
	depth   int
	inClass bool   // directly in a class body
	class   string // name of the class being parsed, and its parent
	parent  string
	traits  []string
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
		p.b.tooDeep()
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
		s := &stmt{kind: sSwitch}
		s.toks, s.funcs = p.group()
		if p.at("{") {
			p.i++
			p.depth++
			s.cases, s.hasDefault = p.switchBody("}")
			p.depth--
		} else if p.php && p.at(":") {
			p.i++
			p.depth++
			s.cases, s.hasDefault = p.switchBody("endswitch")
			p.depth--
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
		s := &stmt{kind: sTry, body: p.bodyStmt()}
		for p.atWord("catch") {
			p.i++
			if p.at("(") {
				p.group()
			}
			s.handlers = append(s.handlers, p.bodyStmt())
		}
		if p.atWord("finally") {
			p.i++
			s.els = p.bodyStmt()
		}
		return s
	case "function":
		if n := next(1); n.Kind == Ident || n.op("&") && next(2).Kind == Ident || n.op("*") {
			return p.funcDecl(true)
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
	case "use":
		if p.php && p.inClass { // use T1, T2; or use T1, T2 { ... } in a class: traits
			p.i++
			for p.i < len(p.t) && !p.at(";") && !p.at("{") {
				if p.t[p.i].Kind == Ident && (p.i+1 >= len(p.t) || !p.t[p.i+1].op(`\`)) {
					p.traits = append(p.traits, p.t[p.i].Text)
				}
				p.i++
			}
			if p.at("{") {
				p.i = closeOf(p.t, p.i) + 1
			} else {
				p.skip(";")
			}
			return nil
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
			public := true
			for k := p.i; k < j; k++ {
				public = public && !p.t[k].word("private") && !p.t[k].word("protected")
			}
			p.i = j
			return p.funcDecl(public)
		}
	}
	return p.simple()
}

func (p *braceParser) nested(f func() []*stmt) []*stmt {
	p.depth++
	defer func() { p.depth-- }()
	return f()
}

// switchBody parses switch cases up to "}" or the PHP word end (both consumed).
// Statements before the first label form a case of their own.
func (p *braceParser) switchBody(end string) (cases [][]*stmt, hasDefault bool) {
	for p.i < len(p.t) && p.b.step() {
		if end == "}" && p.at("}") || end != "}" && p.atWord(end) {
			p.i++
			p.skip(";")
			return
		}
		next := Token{}
		if p.i+1 < len(p.t) {
			next = p.t[p.i+1]
		}
		if p.atWord("case") || p.atWord("default") && (next.op(":") || next.op(";")) {
			hasDefault = hasDefault || p.atWord("default")
			depth := 0
			for p.i < len(p.t) {
				t := p.t[p.i]
				if depth == 0 && (t.op(":") || t.op(";")) || depth == 0 && t.op("}") {
					break
				}
				if isOpen(t) {
					depth++
				} else if isClose(t) {
					depth--
				}
				p.i++
			}
			p.skip(":")
			p.skip(";")
			cases = append(cases, nil)
			continue
		}
		start := p.i
		s := p.statement()
		if len(cases) == 0 {
			cases = append(cases, nil)
		}
		if s != nil {
			cases[len(cases)-1] = append(cases[len(cases)-1], s)
		}
		if p.i == start {
			p.i++
		}
	}
	return
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
func (p *braceParser) funcDecl(public bool) *stmt {
	p.i++
	name := ""
	for p.at("&") || p.at("*") || p.i < len(p.t) && p.t[p.i].Kind == Ident && !p.at("(") {
		if p.t[p.i].Kind == Ident {
			name = p.t[p.i].Text
		}
		p.i++
		if p.i < len(p.t) && p.t[p.i].op("(") {
			break
		}
	}
	method := p.inClass
	f := p.funcRest(p.php)
	if f == nil {
		return nil
	}
	f.name, f.method, f.public = name, method, public && (!strings.HasPrefix(name, "_") || name == "__construct")
	if method {
		f.class, f.parent, f.traits = p.class, p.parent, p.traits
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
	inClass := p.inClass
	p.inClass = false
	defer func() { p.inClass = inClass }()
	return &fn{params: params, fresh: fresh, body: p.nested(func() []*stmt { return p.block(true) })}
}

func (p *braceParser) classStmt() *stmt {
	p.i++
	name, parent := "", ""
	if p.i < len(p.t) && p.t[p.i].Kind == Ident {
		name = p.t[p.i].Text
	}
	depth := 0
	for p.i < len(p.t) {
		t := p.t[p.i]
		if depth == 0 && t.word("extends") && p.i+1 < len(p.t) {
			parent = qualifiedName(p.t, p.i+1)
		}
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
	inClass, class, par, traits := p.inClass, p.class, p.parent, p.traits
	p.inClass, p.class, p.parent, p.traits = true, name, parent, nil
	defer func() { p.inClass, p.class, p.parent, p.traits = inClass, class, par, traits }()
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
			name := p.t[j].Text
			p.i = j + 1
			if f := p.funcRest(false); f != nil {
				f.name, f.method, f.class, f.parent = name, true, p.class, p.parent
				f.public = !strings.HasPrefix(name, "_") && !strings.HasPrefix(name, "#") && p.t[j].Kind == Ident
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
	t       []Token
	i       int
	b       *budget
	depth   int
	inClass bool // directly in a class body
	class   string
	parent  string
	inDef   int // inside this many function bodies
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
		p.b.tooDeep()
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
	method := p.inClass
	inClass, class, par := p.inClass, p.class, p.parent
	p.inClass = kw.Text == "class" || inClass && kw.Text != "def"
	if kw.Text == "class" && len(header) > 0 && header[0].Kind == Ident {
		p.class, p.parent = header[0].Text, ""
		if len(header) > 2 && header[1].op("(") {
			p.parent = qualifiedName(header, 2)
		}
	}
	defer func() { p.inClass, p.class, p.parent = inClass, class, par }()
	inDef := p.inDef
	if kw.Text == "def" {
		p.inDef++
	}
	defer func() { p.inDef = inDef }()
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
		f := &fn{body: body, method: method}
		if method {
			f.class, f.parent = class, par
		}
		if len(header) > 0 && header[0].Kind == Ident {
			f.name = header[0].Text
			f.public = inDef == 0 && (!strings.HasPrefix(f.name, "_") || f.name == "__init__") // a nested def is no API
		}
		if len(header) > 1 && header[1].op("(") {
			f.params = header[2:max(2, closeOf(header, 1))]
		}
		return []*stmt{{kind: sFunc, fn: f}}
	case "except", "else", "case":
		return []*stmt{{kind: sBlock, alt: true, body: body}}
	case "try":
		s := &stmt{kind: sTry, body: body}
		for {
			for p.i < len(p.t) && p.t[p.i].Kind == Newline {
				p.i++
			}
			if p.i >= len(p.t) {
				break
			}
			w := p.t[p.i]
			if !w.word("except") && !w.word("else") && !w.word("finally") {
				break
			}
			part := p.statement()
			var b []*stmt
			if len(part) == 1 {
				b = part[0].body
			}
			switch w.Text {
			case "except":
				s.handlers = append(s.handlers, b)
			case "else":
				s.orelse = b
			case "finally":
				s.els = b
			}
		}
		return []*stmt{s}
	}
	return []*stmt{{kind: sBlock, toks: header, body: body}}
}

// qualifiedName reads a name at i that may be qualified (Foo\\Bar, foo.bar).
func qualifiedName(t []Token, i int) string {
	var b strings.Builder
	for ; i < len(t); i++ {
		switch {
		case t[i].Kind == Ident:
			b.WriteString(t[i].Text)
		case t[i].op("\\") || t[i].op("."):
			b.WriteString(t[i].Text)
		default:
			return b.String()
		}
		if i+1 < len(t) && t[i].Kind == Ident && t[i+1].Kind == Ident {
			break
		}
	}
	return b.String()
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
