package engine

import "strings"

// TypeScript is lexed as JavaScript and its type syntax is then taken out of the
// token stream, so the JavaScript parser and rules apply unchanged. Types carry no
// data: annotations, type arguments and parameters, "as" and "satisfies",
// non-null "!", interfaces, type aliases, enums, "declare" statements, "implements"
// and member modifiers are dropped. Decorators are dropped too, except on a
// parameter: "m(@Body() dto: Dto) { ... }" becomes "m(dto) { dto = @Body(); ... }",
// so a rule can name a framework decorator (@Body() in NestJS) as a source.
//
// The rewrite is token based and heuristic. It never adds a token whose line is
// before the one it follows, so line numbers stay in order.

// LexTS lexes a TypeScript file (.ts, .mts, .cts) into JavaScript tokens.
func LexTS(src string) []Token { return lexTS(src, nil, false) }

// LexTSX lexes a TypeScript file with JSX (.tsx). Unlike in .ts, "<T>x" is an
// element, not a type assertion.
func LexTSX(src string) []Token { return lexTS(src, nil, true) }

func lexTS(src string, b *budget, tsx bool) []Token {
	s := &scanner{src: src, line: 1, b: b, ts: true, jsx: tsx}
	if s.has("#!") {
		s.skipLine()
	}
	s.js(false)
	s.jsxEnd()
	return normalizeModules(stripTS(s.toks, b, tsx))
}

// isTS reports whether lang is a TypeScript dialect, and baseLang maps a dialect
// (jsx, ts, tsx) to the language whose rules, parser and analysis it uses.
func isTS(lang string) bool { return lang == "ts" || lang == "tsx" }

func baseLang(lang string) string {
	if isTS(lang) || lang == "jsx" {
		return "js"
	}
	return lang
}

// tsModifiers are dropped before a member or parameter name.
var tsModifiers = words("public private protected readonly abstract override declare accessor")

// tsNotValue are words after which a token cannot be a postfix operator ("x!",
// "x as T", "f<T>()"): they end no expression.
var tsNotValue = words("return throw yield await new delete void typeof in instanceof function case const let var " +
	"if else do while for switch try catch finally class extends implements import export from default of")

type tsCtx struct {
	kind      byte    // 'b' block, 'o' object literal, 'c' class body, 'p' parentheses, 'k' brackets
	ctl       bool    // 'p': an if/while/for/with header
	noStrip   bool    // the braces of an import or export list
	ternary   int     // open "?" waiting for their ":"
	caseOpen  bool    // a case label waiting for its ":"
	decl      bool    // inside a let/const/var statement
	classNext bool    // the next "{" opens a class body
	module    bool    // inside an import/export statement
	decos     []Token // 'p': decorators of the parameter being read
	decoName  string  // 'p': that parameter's name
	decoPat   int     // 'p': index in out of a decorated parameter's pattern ({ a } or [a]), or -1
	inject    []Token // 'p': statements for the body that follows
	openAt    int     // index in out of the opening token
}

type tsStrip struct {
	in        []Token
	i         int
	out       []Token
	b         *budget
	tsx       bool
	ctx       []*tsCtx
	nlLine    int     // a dropped token started this line: the next token on it starts the line
	inject    []Token // statements to put at the start of the next "{" if it comes next
	lastOpen  int     // index in out of the opener of the last closed bracket
	stmtColon bool    // the last ":" ended a case or a label
}

func stripTS(in []Token, b *budget, tsx bool) []Token {
	x := &tsStrip{in: in, b: b, tsx: tsx, ctx: []*tsCtx{{kind: 'b', openAt: -1, decoPat: -1}}, lastOpen: -1}
	x.run()
	return x.out
}

func (x *tsStrip) at(i int) Token {
	if i >= 0 && i < len(x.in) {
		return x.in[i]
	}
	return Token{Kind: Op}
}

func (x *tsStrip) back(k int) Token {
	if n := len(x.out) - k; n >= 0 {
		return x.out[n]
	}
	return Token{Kind: Op}
}

func (x *tsStrip) top() *tsCtx { return x.ctx[len(x.ctx)-1] }

// drop skips tokens [from, to) of the input.
func (x *tsStrip) drop(from, to int) {
	for k := from; k < to && k < len(x.in); k++ {
		if x.in[k].Flags&FlagNL != 0 {
			x.nlLine = x.in[k].Line
		}
	}
	x.i = max(to, from+1)
}

func (x *tsStrip) emit(t Token) {
	if x.nlLine != 0 {
		if t.Line == x.nlLine {
			t.Flags |= FlagNL
		}
		x.nlLine = 0
	}
	if len(t.Parts) > 0 {
		parts := make([]Part, len(t.Parts))
		for k, p := range t.Parts {
			parts[k] = Part{Off: p.Off, Toks: stripTS(p.Toks, x.b, x.tsx)}
		}
		t.Parts = parts
	}
	inj := x.inject
	x.inject = nil
	x.out = append(x.out, t)
	if len(inj) > 0 && t.op("{") {
		for _, it := range inj {
			it.Line, it.Flags = t.Line, 0
			x.out = append(x.out, it)
		}
	}
}

// value reports whether t ends an expression, so what follows is postfix.
func value(t Token) bool {
	switch t.Kind {
	case Ident:
		return !tsNotValue[t.Text]
	case Num, Str, Var:
		return true
	case Op:
		return t.Text == ")" || t.Text == "]" || t.Text == "}"
	}
	return false
}

// stmtStart reports whether the token at x.i begins a statement.
func (x *tsStrip) stmtStart() bool {
	p := x.back(1)
	if len(x.out) == 0 || x.in[x.i].Flags&FlagNL != 0 && !p.op(".") {
		return true
	}
	return p.op(";") || p.op("{") || p.op("}") || p.word("export") || p.word("default") || p.word("declare")
}

// unexport removes a trailing "export", "export default" or "declare" before a dropped declaration.
func (x *tsStrip) unexport() {
	for n := len(x.out); n > 0 && (x.out[n-1].word("export") || x.out[n-1].word("default") || x.out[n-1].word("declare")); n-- {
		x.out = x.out[:n-1]
	}
}

func (x *tsStrip) run() {
	for x.i < len(x.in) && x.b.step() {
		t := x.in[x.i]
		c := x.top()
		if t.Flags&FlagNL != 0 && !x.back(1).op(",") {
			c.decl, c.module = false, false
		}
		switch {
		case t.Kind == Ident && strings.HasPrefix(t.Text, "@"):
			x.decorator(c)
		case t.Kind == Ident:
			x.ident(t, c)
		case t.op("?"):
			if n := x.at(x.i + 1); !c.noStrip && (n.op(":") || n.op(",") || n.op(")") || n.op(";") || n.op("=") || c.kind == 'c' && n.op("(") && x.memberName()) {
				x.drop(x.i, x.i+1) // optional parameter, field or method
				continue
			}
			c.ternary++
			x.next(t)
		case t.op("!"):
			if p := x.back(1); t.Flags&FlagNL == 0 && value(p) && !p.op("}") && !(p.op(")") && x.ctlClosed()) {
				x.drop(x.i, x.i+1) // non-null assertion or definite assignment
				continue
			}
			x.next(t)
		case t.op(":"):
			x.colon(t, c)
		case t.op("<"):
			x.angle(t, c)
		case t.op("(") || t.op("[") || t.op("{"):
			x.open(t, c)
		case t.op(")") || t.op("]") || t.op("}"):
			x.close(t, c)
		case t.op(";"):
			c.ternary, c.decl, c.module, c.caseOpen = 0, false, false, false
			x.next(t)
		case t.op(","):
			c.ternary = 0
			if c.kind == 'p' {
				x.paramEnd(c)
			}
			x.next(t)
		default:
			x.next(t)
		}
	}
}

func (x *tsStrip) next(t Token) {
	x.emit(t)
	x.i++
}

// ctlClosed reports whether the last ")" in out closed an if/while/for/with header.
func (x *tsStrip) ctlClosed() bool {
	o := x.lastOpen
	return o > 0 && x.out[o].op("(") && x.out[o-1].Kind == Ident && ctlWords[x.out[o-1].Text]
}

func (x *tsStrip) ident(t Token, c *tsCtx) {
	n1, n2 := x.at(x.i+1), x.at(x.i+2)
	sameLine := func(t Token) bool { return t.Flags&FlagNL == 0 }
	if c.noStrip {
		if t.Text == "type" && n1.Kind == Ident && sameLine(n1) && !n1.word("as") {
			x.drop(x.i, x.i+1) // import { type A }
			return
		}
		x.next(t)
		return
	}
	if x.back(1).op(".") || x.back(1).op("?.") {
		x.member(t)
		return
	}
	start := x.stmtStart()
	switch {
	case start && t.Text == "interface" && n1.Kind == Ident && sameLine(n1):
		j := x.i + 2
		for j < len(x.in) && !x.at(j).op("{") && !x.at(j).op(";") && x.b.step() {
			j = max(x.skipType(j), j+1)
		}
		if x.at(j).op("{") {
			if e, ok := x.matchOK(j); ok {
				j = e + 1
			} // unclosed: only the header goes, the rest is read as code (and reported partial)
		}
		x.unexport()
		x.drop(x.i, j)
		return
	case start && t.Text == "type" && n1.Kind == Ident && sameLine(n1) && (n2.op("=") || n2.op("<")):
		j := x.i + 2
		if n2.op("<") {
			j, _ = x.angles(j, false)
		}
		if x.at(j).op("=") {
			j = x.skipType(j + 1)
		}
		if x.at(j).op(";") {
			j++
		}
		x.unexport()
		x.drop(x.i, j)
		return
	case t.Text == "type" && (x.back(1).word("import") || x.back(1).word("export")) && (n1.op("{") || n1.op("*") || n1.Kind == Ident && !n1.word("from")):
		x.drop(x.i, x.i+1) // import type X from, export type { X }
		return
	case (start || x.back(1).word("const")) && t.Text == "enum" && n1.Kind == Ident && sameLine(n1) && n2.op("{"):
		if x.back(1).word("const") {
			x.out = x.out[:len(x.out)-1]
		}
		x.unexport()
		if e, ok := x.matchOK(x.i + 2); ok {
			x.drop(x.i, e+1)
		} else {
			x.drop(x.i, x.i+2) // unclosed: the body is read as code (and reported partial)
		}
		return
	case start && t.Text == "declare" && n1.Kind == Ident && sameLine(n1) && c.kind != 'c':
		x.unexport()
		x.drop(x.i, x.declEnd(x.i+1))
		return
	case start && (t.Text == "namespace" || t.Text == "module") && (n1.Kind == Ident || n1.Kind == Str && t.Text == "module") && sameLine(n1):
		j := x.i + 2
		for x.at(j).op(".") && x.at(j+1).Kind == Ident {
			j += 2
		}
		if x.at(j).op("{") {
			x.unexport()
			x.drop(x.i, j) // the body is ordinary code in a block
			return
		}
	case t.Text == "import" && start && n1.Kind == Ident && n2.op("="):
		t.Text = "const" // import x = require("m")
		x.next(t)
		return
	case t.Text == "this" && x.back(1).op("(") && n1.op(":") && c.kind == 'p':
		j := x.skipType(x.i + 2) // function f(this: Window, ...)
		if x.at(j).op(",") {
			j++
		}
		x.drop(x.i, j)
		return
	case tsModifiers[t.Text] && (c.kind == 'c' || c.kind == 'p' || t.Text == "abstract" && n1.word("class")) && sameLine(n1) &&
		(n1.Kind == Ident || n1.op("[") || n1.Kind == Str || n1.op("*")):
		x.drop(x.i, x.i+1)
		return
	case t.Text == "implements" && c.classNext:
		j := x.i + 1
		for j < len(x.in) && !x.at(j).op("{") && x.b.step() {
			j = max(x.skipType(j), j+1)
		}
		x.drop(x.i, j)
		return
	case (t.Text == "as" || t.Text == "satisfies") && value(x.back(1)) && sameLine(t) && !c.module && x.typeStart(n1):
		if n1.word("const") {
			x.drop(x.i, x.i+2)
		} else {
			x.drop(x.i, x.skipType(x.i+1))
		}
		return
	case t.Text == "class" && (n1.Kind == Ident || n1.op("{")):
		c.classNext = true
	case t.Text == "let" || t.Text == "const" || t.Text == "var":
		c.decl = true
	case t.Text == "case":
		c.caseOpen = true
	case start && (t.Text == "import" && !n1.op("(") && !n1.op(".") || t.Text == "export" && (n1.op("{") || n1.op("*") || n1.word("type"))):
		c.module = true // an import or export list: "a as b" renames
	}
	if c.kind == 'p' && len(c.decos) > 0 && c.decoName == "" {
		c.decoName = t.Text
	}
	x.next(t)
	x.typeArgs(t)
}

// member emits a name after "." and the type arguments of a call on it.
func (x *tsStrip) member(t Token) {
	x.next(t)
	x.typeArgs(t)
}

// typeArgs drops "<...>" after a name when it is a type argument or parameter
// list: f<T>(x), new Map<K, V>(), class A<T> extends B<T> {.
func (x *tsStrip) typeArgs(name Token) {
	if !x.at(x.i).op("<") || x.at(x.i).Flags&FlagNL != 0 || tsNotValue[name.Text] {
		return
	}
	j, ok := x.angles(x.i, true)
	if !ok {
		return
	}
	k := len(x.out) - 1 // the name; pre is the token before its dotted chain
	for k >= 2 && x.out[k-1].op(".") && x.out[k-2].Kind == Ident {
		k -= 2
	}
	pre := Token{Kind: Op}
	if k >= 1 {
		pre = x.out[k-1]
	}
	heritage := pre.word("class") || pre.word("extends") || pre.word("implements") || pre.word("new") || x.top().classNext
	if n := x.at(j); n.op("(") || n.Kind == Str && n.Line == x.at(j-1).Line || heritage && (n.op("{") || n.word("extends") || n.word("implements") || n.op(",")) ||
		pre.word("new") {
		x.drop(x.i, j)
	}
}

// angle handles "<" where it is not after a name: a generic arrow function
// "<T>(x: T) => x" or, in .ts only, a type assertion "<T>x".
func (x *tsStrip) angle(t Token, c *tsCtx) {
	if !value(x.back(1)) && !c.noStrip {
		if j, ok := x.angles(x.i, true); ok {
			arrow := x.at(j).op("(")
			if x.tsx {
				// <T,>(x) => x or <T extends U>(x) => x; anything else is an element.
				n1, n2 := x.at(x.i+1), x.at(x.i+2)
				arrow = arrow && n1.Kind == Ident && (n2.op(",") || n2.word("extends"))
			}
			if arrow || !x.tsx {
				x.drop(x.i, j)
				return
			}
		}
	}
	x.next(t)
}

// memberName reports whether the last token in out is a class member's name.
func (x *tsStrip) memberName() bool {
	p, b := x.back(1), x.back(2)
	return p.Kind == Ident && (b.op("{") || b.op(";") || b.op("}") || b.word("static") || b.word("async") ||
		p.Flags&FlagNL != 0 && (b.Kind != Op || b.op(")"))) // not "h =\n ok ? a : b"
}

// validPipes are NestJS pipes that turn a parameter into a number, boolean, UUID or enum value.
var validPipes = words("ParseIntPipe ParseFloatPipe ParseBoolPipe ParseUUIDPipe ParseEnumPipe")

func (x *tsStrip) decorator(c *tsCtx) {
	j := x.i + 1
	for x.at(j).op(".") && x.at(j+1).Kind == Ident {
		j += 2
	}
	if x.at(j).op("(") {
		e, ok := x.matchOK(j)
		if !ok {
			x.drop(x.i, j) // @D( unclosed: the arguments are read as code (and reported partial)
			return
		}
		j = e + 1
	}
	if c.kind == 'p' {
		c.decos = append(c.decos, x.in[x.i:min(j, len(x.in))]...)
	}
	x.drop(x.i, j)
}

// paramEnd closes the parameter being read: a decorated parameter becomes an
// assignment at the start of the body.
func (x *tsStrip) paramEnd(c *tsCtx) {
	target := []Token{{Kind: Ident, Text: c.decoName}}
	if c.decoPat >= 0 {
		// let { cmd } = @Body(); (a fresh copy of the pattern, without line starts)
		end, depth := c.decoPat, 0
		for k := c.decoPat; k < len(x.out); k++ {
			if isOpen(x.out[k]) {
				depth++
			} else if isClose(x.out[k]) {
				if depth--; depth == 0 {
					end = k
					break
				}
			}
		}
		target = []Token{{Kind: Ident, Text: "let"}}
		for _, t := range x.out[c.decoPat : end+1] {
			t.Flags &^= FlagNL
			target = append(target, t)
		}
	}
	if len(c.decos) > 0 && c.decoName != "" {
	decos:
		for _, d := range splitDecos(c.decos) {
			for _, t := range d {
				if t.Kind == Ident && validPipes[t.Text] {
					continue decos
				}
			}
			if d[0].word("@Req") || d[0].word("@Request") {
				// The whole request is not input (req.user is the server's own), its parts are.
				if c.decoPat < 0 {
					for _, k := range []string{"query", "body", "params", "headers", "cookies", "originalUrl", "url", "get", "header"} {
						c.inject = append(c.inject, Token{Kind: Ident, Text: c.decoName}, Token{Kind: Op, Text: "."}, Token{Kind: Ident, Text: k}, Token{Kind: Op, Text: "="})
						c.inject = append(append(c.inject, d...), Token{Kind: Op, Text: ";"})
					}
					continue
				}
			}
			c.inject = append(append(c.inject, target...), Token{Kind: Op, Text: "="})
			c.inject = append(append(c.inject, d...), Token{Kind: Op, Text: ";"})
		}
	}
	c.decos, c.decoName, c.decoPat = nil, "", -1
}

func splitDecos(t []Token) [][]Token {
	var out [][]Token
	for k := 0; k < len(t); k++ {
		if t[k].Kind == Ident && strings.HasPrefix(t[k].Text, "@") || len(out) == 0 {
			out = append(out, nil)
		}
		out[len(out)-1] = append(out[len(out)-1], t[k])
	}
	return out
}

func (x *tsStrip) colon(t Token, c *tsCtx) {
	p := x.back(1)
	typ := false
	switch {
	case c.noStrip:
	case c.ternary > 0:
		c.ternary--
	case c.caseOpen || p.word("default"):
		c.caseOpen = false
		x.stmtColon = true
	case p.op(")"):
		typ = !x.ctlClosed() // return type of a function, method or arrow
	case c.kind == 'c':
		typ = true // field type or index signature
	case c.kind == 'p':
		typ = x.paramName(p)
	case c.kind == 'b':
		typ = x.declName(p, c)
		x.stmtColon = !typ // a label
	}
	if typ {
		x.drop(x.i, x.skipType(x.i+1))
		return
	}
	x.next(t)
}

// paramName reports whether p, the last token in out, is a parameter name or pattern.
func (x *tsStrip) paramName(p Token) bool {
	k := len(x.out) - 1
	if p.op("}") || p.op("]") {
		k = x.lastOpen
	} else if p.Kind != Ident {
		return false
	}
	if k <= 0 {
		return false
	}
	b := x.out[k-1]
	return b.op("(") || b.op(",") || b.op("...")
}

// declName reports whether p is the name or pattern declared by let/const/var.
func (x *tsStrip) declName(p Token, c *tsCtx) bool {
	k := len(x.out) - 1
	if p.op("}") || p.op("]") {
		k = x.lastOpen
	} else if p.Kind != Ident {
		return false
	}
	if k <= 0 {
		return false
	}
	b := x.out[k-1]
	return b.word("let") || b.word("const") || b.word("var") || c.decl && b.op(",")
}

func (x *tsStrip) open(t Token, c *tsCtx) {
	n := &tsCtx{kind: 'p', decoPat: -1}
	p := x.back(1)
	if c.kind == 'p' && len(c.decos) > 0 && c.decoName == "" && (t.op("{") || t.op("[")) {
		c.decoName, c.decoPat = "{", len(x.out) // run(@Body() { cmd }: Dto)
	}
	switch t.Text {
	case "(":
		n.ctl = p.Kind == Ident && ctlWords[p.Text] && !x.back(2).op(".")
	case "[":
		n.kind = 'k'
	case "{":
		switch {
		case c.classNext:
			n.kind = 'c'
			c.classNext = false
		case c.module && (p.word("import") || p.word("export") || p.word("type") || p.op(",")):
			n.kind, n.noStrip = 'o', true
		case len(x.out) == 0, p.op(")"), p.op("=>"), p.op(";"), p.op("{"), p.op("}"):
			n.kind = 'b'
		case p.op(":") && x.stmtColon:
			n.kind = 'b'
		case p.Kind == Op, p.Kind == Ident && tsNotValue[p.Text] && !(p.word("else") || p.word("do") || p.word("try") || p.word("finally")):
			n.kind = 'o'
		default:
			n.kind = 'b'
		}
	}
	x.stmtColon = false
	n.openAt = len(x.out)
	x.ctx = append(x.ctx, n)
	x.next(t)
}

func (x *tsStrip) close(t Token, c *tsCtx) {
	if len(x.ctx) == 1 {
		x.next(t)
		return
	}
	if c.kind == 'p' {
		x.paramEnd(c)
	}
	x.ctx = x.ctx[:len(x.ctx)-1]
	x.lastOpen = c.openAt
	x.next(t)
	if len(c.inject) > 0 {
		x.inject = c.inject
	}
}

// declEnd returns the end of a "declare" statement starting at i.
func (x *tsStrip) declEnd(i int) int {
	depth := 0
	for j := i; j < len(x.in) && x.b.step(); j++ {
		t := x.in[j]
		switch {
		case isOpen(t):
			depth++
		case isClose(t):
			if depth--; depth <= 0 && t.op("}") {
				if depth < 0 {
					return j
				}
				if n := x.at(j + 1); n.op(";") {
					return j + 2
				} else if n.Flags&FlagNL != 0 || j+1 >= len(x.in) {
					return j + 1
				}
			}
		case depth == 0 && t.op(";"):
			return j + 1
		case depth == 0 && j > i+1 && t.Flags&FlagNL != 0 && !continues(x.in[j-1]) && !continues(t):
			return j
		}
	}
	if depth > 0 {
		x.b.unterminated() // declare module 'm' { unclosed: only "declare" goes
		return i
	}
	return len(x.in)
}

// continues reports whether t joins the lines before and after it in a type.
func continues(t Token) bool {
	return t.Kind == Op && (t.Text == "|" || t.Text == "&" || t.Text == "=" || t.Text == "," || t.Text == ":" ||
		t.Text == "=>" || t.Text == "." || t.Text == "?" || t.Text == "<")
}

// match returns the index of the bracket closing the one at i (or the last token).
func (x *tsStrip) match(i int) int {
	depth := 0
	for j := i; j < len(x.in) && x.b.step(); j++ {
		if isOpen(x.in[j]) {
			depth++
		} else if isClose(x.in[j]) {
			if depth--; depth <= 0 {
				return j
			}
		}
	}
	return len(x.in) - 1
}

// matchOK is match for code that is dropped: an unclosed bracket is reported
// (ErrPartial) instead of taking the rest of the file with it.
func (x *tsStrip) matchOK(i int) (int, bool) {
	depth := 0
	for j := i; j < len(x.in) && x.b.step(); j++ {
		if isOpen(x.in[j]) {
			depth++
		} else if isClose(x.in[j]) {
			if depth--; depth <= 0 {
				return j, true
			}
		}
	}
	x.b.unterminated()
	return i, false
}

// typeGroup checks the bracket group at i inside type arguments: types only,
// no call (exec(x)) and no value operators. It returns the index of its closer.
func (x *tsStrip) typeGroup(i, depth int) (int, bool) {
	if depth > maxNest {
		return i, false
	}
	for j := i + 1; j < len(x.in) && x.b.step(); j++ {
		t := x.in[j]
		switch {
		case isClose(t):
			return j, true
		case isOpen(t):
			if t.op("(") && j > i+1 && x.in[j-1].Kind == Ident && !x.in[j-1].word("new") {
				return i, false // a call is a value
			}
			e, ok := x.typeGroup(j, depth+1)
			if !ok || x.at(e+1).op("(") {
				return i, false // (exec)(x), (0, eval)(x): a call
			}
			j = e
		case t.Kind == Ident || t.Kind == Str || t.Kind == Num:
		case t.Kind == Op && (typeOps[t.Text] || t.Text == ";" || t.Text == "<" || t.Text == ">" || t.Text == ">>"):
		default:
			return i, false
		}
		if j-i > maxAngles {
			return i, false
		}
	}
	return i, false
}

// maxAngles bounds the look-ahead of a "<" that may be a comparison.
const maxAngles = 512

// angles reads "<...>" at i and returns the index after it. With check, the
// content must look like types (no operators that only values have), and the
// look-ahead is bounded.
func (x *tsStrip) angles(i int, check bool) (int, bool) {
	depth := 0
	for j := i; j < len(x.in) && x.b.step(); j++ {
		if check && j-i > maxAngles {
			return i, false
		}
		t := x.in[j]
		switch {
		case t.op("<"):
			depth++
		case t.op(">"):
			depth--
		case t.op(">>"):
			depth -= 2
		case t.op(">>>"):
			depth -= 3
		case t.op("(") || t.op("[") || t.op("{"):
			if !check {
				j = x.match(j)
				continue
			}
			if t.op("(") && j > i && x.in[j-1].Kind == Ident && !x.in[j-1].word("new") {
				return i, false // f(a < g(x), b > (y)): a call inside is no type
			}
			e, ok := x.typeGroup(j, 0)
			if !ok || x.at(e+1).op("(") {
				return i, false // f(a < (exec)(c), b > (0)): a call through parentheses
			}
			j = e
			continue
		case t.Kind == Ident || t.Kind == Str || t.Kind == Num:
			continue
		case t.Kind == Op && typeOps[t.Text]:
			continue
		default:
			if check || isClose(t) || t.op(";") {
				return i, false
			}
		}
		if depth < 0 {
			return i, false
		}
		if depth == 0 {
			return j + 1, true
		}
	}
	return i, false
}

var typeOps = words(". , | & ? : => = ... -")

// typeStart reports whether t can begin a type.
func (x *tsStrip) typeStart(t Token) bool {
	return t.Kind == Ident || t.Kind == Str || t.Kind == Num || t.op("{") || t.op("[") || t.op("(") || t.op("<") || t.op("-")
}

// skipType returns the index after the type starting at i.
func (x *tsStrip) skipType(i int) int {
	i = x.skipUnion(i)
	if t := x.at(i); t.word("extends") && t.Flags&FlagNL == 0 {
		i = x.skipUnion(i + 1)
		if x.at(i).op("?") {
			i = x.skipType(i + 1)
			if x.at(i).op(":") {
				i = x.skipType(i + 1)
			}
		}
	}
	return i
}

func (x *tsStrip) skipUnion(i int) int {
	if x.at(i).op("|") || x.at(i).op("&") {
		i++
	}
	for x.b.step() {
		j := x.skipPostfix(i)
		if j == i {
			return i
		}
		i = j
		if !x.at(i).op("|") && !x.at(i).op("&") {
			return i
		}
		i++
	}
	return i
}

func (x *tsStrip) skipPostfix(i int) int {
	j := x.skipPrimary(i)
	if j == i {
		return i
	}
	for x.at(j).op("[") && x.at(j).Flags&FlagNL == 0 && x.b.step() {
		e, ok := x.matchOK(j)
		if !ok {
			return j
		}
		j = e + 1
	}
	return j
}

func (x *tsStrip) skipPrimary(i int) int {
	t := x.at(i)
	if i >= len(x.in) {
		return i
	}
	switch {
	case t.word("typeof") || t.word("keyof") || t.word("readonly") || t.word("unique") || t.word("infer") || t.word("asserts"):
		if x.at(i+1).op("|") || x.at(i+1).op("&") || x.at(i+1).op(",") || x.at(i+1).op(")") || x.at(i+1).op(">") || x.at(i+1).op("=") || x.at(i+1).op(";") {
			return i + 1 // the word used as a type name
		}
		return x.skipPostfix(i + 1)
	case t.word("new") && x.at(i+1).op("("):
		return x.skipPrimary(i + 1)
	case t.Kind == Ident:
		j := i + 1
		for x.at(j).op(".") && x.at(j+1).Kind == Ident {
			j += 2
		}
		if x.at(j).op("<") && x.at(j).Flags&FlagNL == 0 {
			j, _ = x.angles(j, false)
		}
		if x.at(j).word("is") {
			return x.skipType(j + 1) // a type predicate: x is T
		}
		return j
	case t.Kind == Str || t.Kind == Num:
		return i + 1
	case t.op("-") && x.at(i+1).Kind == Num:
		return i + 2
	case t.op("{") || t.op("["):
		if e, ok := x.matchOK(i); ok {
			return e + 1
		}
		return i // unclosed: read as code (and reported partial)
	case t.op("("):
		e, ok := x.matchOK(i)
		if !ok {
			return i
		}
		j := e + 1
		if x.at(j).op("=>") {
			return x.skipType(j + 1)
		}
		return j
	case t.op("<"):
		if j, ok := x.angles(i, false); ok && x.at(j).op("(") {
			return x.skipPrimary(j)
		}
	}
	return i
}
