package engine

import "strings"

// Node's core modules are reached in many spellings: fs.readFileSync(p),
// fs.promises.readFile(p), require('fs').readFileSync(p), fsp.readFile(p) after
// import fsp from 'fs/promises', or r(p) after const { readFileSync: r } =
// require('fs'). normalizeModules rewrites each of them to one form, the module
// name, ".", the function (fs.readFileSync(p)), and flags the module name with
// FlagModule. A rule then names a sink once: "fs.readFile(" or "readFileSync(";
// a sink written as a bare name also matches it as a member of a flagged module
// (see pat.at), but never as a method of any other object (re.exec(s)).

// coreModules maps module specifiers to the name used in the rewrite.
var coreModules = map[string]string{
	"fs": "fs", "fs/promises": "fs", "child_process": "child_process", "vm": "vm",
}

func moduleOf(spec string) string {
	return coreModules[strings.TrimPrefix(spec, "node:")]
}

type modBinding struct {
	mod, member string // member "" binds the module itself
}

// normalizeModules applies the rewrite to a JavaScript (or stripped
// TypeScript) token stream.
func normalizeModules(toks []Token) []Token {
	t := joinArrays(unwrapCallees(toks))
	m := &modScope{t: t, cl: closers(t), binds: map[string][]scoped{}, shadows: map[string][]scoped{}, tooMany: map[string]bool{}}
	m.enc = enclosing(t, m.cl)
	m.collect()
	if len(m.binds) == 0 {
		return t
	}
	m.declarations()
	return m.rewrite(t, 0)
}

// scoped is a binding of a name, or a declaration that hides it, from token from
// to token to (the end of its block or function).
type scoped struct {
	modBinding
	from, to int
}

type modScope struct {
	t       []Token
	cl, enc []int
	binds   map[string][]scoped // names bound to a module or one of its functions
	shadows map[string][]scoped // other declarations of those names
	tooMany map[string]bool     // names declared too often to follow: never rewritten
}

// maxScoped bounds the bindings and declarations kept per name, so each look-up
// stays cheap on a hostile file; a name over it is left as it is.
const maxScoped = 64

// enclosing returns, for each token, the index of the "}" ending the innermost
// block around it (len(t) at the top level).
func enclosing(t []Token, cl []int) []int {
	enc := make([]int, len(t))
	var stack []int
	for i, tk := range t {
		enc[i] = len(t)
		if n := len(stack); n > 0 {
			enc[i] = cl[stack[n-1]]
		}
		switch {
		case tk.op("{"):
			stack = append(stack, i)
		case tk.op("}") && len(stack) > 0:
			stack = stack[:len(stack)-1]
		}
	}
	return enc
}

func (m *modScope) at(i int) Token {
	if i >= 0 && i < len(m.t) {
		return m.t[i]
	}
	return Token{Kind: Op}
}

func (m *modScope) add(name string, b modBinding, at int) {
	if m.tooMany[name] {
		return
	}
	if len(m.binds[name]) >= maxScoped {
		m.tooMany[name] = true
		delete(m.binds, name)
		return
	}
	m.binds[name] = append(m.binds[name], scoped{b, at, m.enc[at]})
}

// resolve returns the binding of name in force at token u: the latest one whose
// scope holds u, unless a later declaration of the name in a scope holding u
// hides it.
func (m *modScope) resolve(name string, u int) (modBinding, bool) {
	if m.tooMany[name] {
		return modBinding{}, false
	}
	best := scoped{from: -1}
	for _, b := range m.binds[name] {
		if b.from <= u && u <= b.to && b.from > best.from {
			best = b
		}
	}
	if best.from < 0 {
		return modBinding{}, false
	}
	for _, d := range m.shadows[name] {
		if d.from > best.from && d.from <= u && u <= d.to {
			return modBinding{}, false
		}
	}
	return best.modBinding, true
}

// joinArrays rewrites [a, b].join(s) to (a + s + b), so a value joined from an
// array of parts is built from each part, as a concatenation is: a sink that
// needs the SQL text itself built from input then sees it.
func joinArrays(t []Token) []Token {
	cl := closers(t)
	var out []Token
	for i := 0; i < len(t); i++ {
		c := closeAt(cl, i)
		if t[i].op("[") && (len(out) == 0 || !jsValue(out[len(out)-1])) && c+3 < len(t) && t[c+1].op(".") && t[c+2].word("join") && t[c+3].op("(") {
			e := closeAt(cl, c+3)
			if e < len(t) && c-i > 1 {
				sep := t[c+4 : e]
				if len(sep) == 0 {
					sep = []Token{{Kind: Str, Text: ",", Line: t[c].Line}}
				}
				line := t[i]
				line.Text = "("
				out = append(out, line)
				for k, part := range splitTop(t[i+1:c], isOp(",")) {
					if len(part) > 0 && part[0].op("...") {
						part = part[1:]
					}
					if k > 0 {
						out = append(out, Token{Kind: Op, Text: "+", Line: part0Line(part, line.Line)})
						out = append(out, sep...)
						out = append(out, Token{Kind: Op, Text: "+", Line: part0Line(part, line.Line)})
					}
					out = append(out, part...)
				}
				out = append(out, Token{Kind: Op, Text: ")", Line: t[e].Line})
				i = e
				continue
			}
		}
		out = append(out, t[i])
	}
	return out
}

func part0Line(part []Token, def int) int {
	if len(part) > 0 {
		return part[0].Line
	}
	return def
}

// unwrapCallees rewrites a parenthesised callee to a plain one: (exec)(x) and
// the indirect call (0, eval)(x) call exec and eval like exec(x) and eval(x).
func unwrapCallees(t []Token) []Token {
	var out []Token
	for i := 0; i < len(t); i++ {
		if t[i].op("(") && (len(out) == 0 || !jsValue(out[len(out)-1])) {
			switch {
			case i+3 < len(t) && t[i+1].Kind == Ident && t[i+2].op(")") && t[i+3].op("("):
				out = append(out, t[i+1])
				i += 2
				continue
			case i+5 < len(t) && t[i+1].Kind == Num && t[i+2].op(",") && t[i+3].Kind == Ident && t[i+4].op(")") && t[i+5].op("("):
				out = append(out, t[i+3])
				i += 4
				continue
			}
		}
		if out == nil {
			out = make([]Token, 0, len(t))
			out = append(out, t[:i]...)
		}
		out = append(out, t[i])
	}
	if out == nil {
		return t
	}
	return out
}

// requireAt reports the module of "require('m')" at i and the index after it,
// also after ".promises".
func requireAt(t []Token, i int) (string, int) {
	if i+3 < len(t) && t[i].word("require") && t[i+1].op("(") && t[i+2].Kind == Str && len(t[i+2].Parts) == 0 && t[i+3].op(")") &&
		(i == 0 || !memberOp(false, t[i-1])) {
		if m := moduleOf(t[i+2].Text); m != "" {
			j := i + 4
			if j+1 < len(t) && t[j].op(".") && t[j+1].word("promises") {
				j += 2
			}
			return m, j
		}
	}
	return "", i
}

// closers returns, for each opening bracket, the index of the one closing it
// (len(t) when none does), in one pass, so look-ups cost nothing on hostile input.
func closers(t []Token) []int {
	cl := make([]int, len(t))
	var stack []int
	for i, tk := range t {
		cl[i] = len(t)
		switch {
		case isOpen(tk):
			stack = append(stack, i)
		case isClose(tk) && len(stack) > 0:
			cl[stack[len(stack)-1]] = i
			stack = stack[:len(stack)-1]
		}
	}
	return cl
}

func (m *modScope) collect() {
	t, cl := m.t, m.cl
	at := m.at
	for i := 0; i < len(t); i++ {
		switch {
		case (t[i].word("const") || t[i].word("let") || t[i].word("var")) && at(i+1).Kind == Ident && at(i+2).op("="):
			// const fs = require('fs'), const fsp = require('fs').promises
			if mod, j := requireAt(t, i+3); mod != "" {
				if at(j).op(".") && at(j+1).Kind == Ident && !at(j+2).op("(") {
					m.add(t[i+1].Text, modBinding{mod: mod, member: t[j+1].Text}, i) // const run = require('child_process').exec
				} else {
					m.add(t[i+1].Text, modBinding{mod: mod}, i)
				}
			} else if b, ok := m.resolve(at(i+3).Text, i+3); ok && at(i+3).Kind == Ident && b.member == "" && !at(i+4).op(".") && !at(i+4).op("(") {
				m.add(t[i+1].Text, b, i) // const c = cp0
			} else if b, ok := m.resolve(at(i+3).Text, i+3); ok && b.member == "" && at(i+4).op(".") && at(i+5).word("promises") {
				m.add(t[i+1].Text, b, i) // const fsp = fs.promises
			}
		case (t[i].word("const") || t[i].word("let") || t[i].word("var")) && at(i+1).op("{"):
			// const { readFileSync: r, promises: fsp } = require('fs')
			c := closeAt(cl, i+1)
			if !at(c + 1).op("=") {
				continue
			}
			if mod, _ := requireAt(t, c+2); mod != "" {
				m.destructure(t[i+2:c], mod, ":", i)
			} else if b, ok := m.resolve(at(c+2).Text, c+2); ok && at(c+2).Kind == Ident && b.member == "" && !at(c+3).op(".") {
				m.destructure(t[i+2:c], b.mod, ":", i) // const { exec: run } = cp0
			}
		case t[i].word("import") && (i == 0 || !memberOp(false, t[i-1])):
			// import fs from 'fs'; import * as fs from 'fs'; import { a as b } from 'fs'
			j := i + 1
			for j < len(t) && !t[j].word("from") && !t[j].op(";") && j-i < 256 {
				j++
			}
			if !at(j).word("from") || at(j+1).Kind != Str {
				continue
			}
			mod := moduleOf(t[j+1].Text)
			if mod == "" {
				continue
			}
			for k := i + 1; k < j; k++ {
				switch {
				case t[k].op("{"):
					c := min(closeAt(cl, k), j)
					m.destructure(t[k+1:c], mod, "as", i)
					k = c
				case t[k].op("*") && at(k+1).word("as") && at(k+2).Kind == Ident:
					m.add(t[k+2].Text, modBinding{mod: mod}, i)
					k += 2
				case t[k].Kind == Ident && !t[k].word("type") && (at(k+1).op(",") || at(k+1).word("from")):
					m.add(t[k].Text, modBinding{mod: mod}, i) // the default import
				}
			}
		}
	}
}

// destructure reads "a, b: c" (sep ":") or "a, b as c" (sep "as") from module m.
func (m *modScope) destructure(t []Token, mod, sep string, at int) {
	for _, part := range splitTop(t, isOp(",")) {
		if len(part) == 0 || part[0].Kind != Ident {
			continue
		}
		name, local := part[0].Text, part[0].Text
		if len(part) >= 3 && (sep == ":" && part[1].op(":") || sep == "as" && part[1].word("as")) && part[2].Kind == Ident {
			local = part[2].Text
		}
		if name == "promises" {
			m.add(local, modBinding{mod: mod}, at)
		} else {
			m.add(local, modBinding{mod: mod, member: name}, at)
		}
	}
}

// rewrite rewrites t; base is the index of t[0] in m.t (template fields are
// rewritten with the scope of the token that holds them).
func (m *modScope) rewrite(t []Token, base int) []Token {
	out := make([]Token, 0, len(t))
	modTok := func(m string, from Token) Token {
		return Token{Kind: Ident, Text: m, Line: from.Line, Flags: from.Flags&FlagNL | FlagModule}
	}
	for i := 0; i < len(t); i++ {
		tk := t[i]
		member := i > 0 && memberOp(false, t[i-1])
		if len(tk.Parts) > 0 {
			parts := make([]Part, len(tk.Parts))
			for k, p := range tk.Parts {
				parts[k] = Part{Off: p.Off, Toks: m.rewriteAt(p.Toks, base+i)}
			}
			tk.Parts = parts
		}
		if m, j := requireAt(t, i); m != "" {
			out = append(out, modTok(m, tk))
			i = j - 1
			continue
		}
		if tk.Kind == Ident && !member && i+1 < len(t) {
			b, bound := m.resolve(tk.Text, base+i)
			switch {
			case bound && b.member == "" && t[i+1].op("."):
				out = append(out, modTok(b.mod, tk)) // fsp.readFile( -> fs.readFile(
				if i+3 < len(t) && t[i+2].word("promises") && t[i+3].op(".") {
					i += 2
				}
				continue
			case bound && b.member != "" && t[i+1].op("("):
				out = append(out, modTok(b.mod, tk), Token{Kind: Op, Text: ".", Line: tk.Line},
					Token{Kind: Ident, Text: b.member, Line: tk.Line}) // r(p) -> fs.readFileSync(p)
				continue
			}
		}
		out = append(out, tk)
	}
	return out
}

// rewriteAt rewrites the tokens of a template field held by token u.
func (m *modScope) rewriteAt(t []Token, u int) []Token {
	out := make([]Token, 0, len(t))
	modTok := func(mod string, from Token) Token {
		return Token{Kind: Ident, Text: mod, Line: from.Line, Flags: from.Flags&FlagNL | FlagModule}
	}
	for i := 0; i < len(t); i++ {
		tk := t[i]
		if mod, j := requireAt(t, i); mod != "" {
			out = append(out, modTok(mod, tk))
			i = j - 1
			continue
		}
		if tk.Kind == Ident && !(i > 0 && memberOp(false, t[i-1])) && i+1 < len(t) {
			if b, ok := m.resolve(tk.Text, u); ok {
				switch {
				case b.member == "" && t[i+1].op("."):
					out = append(out, modTok(b.mod, tk))
					continue
				case b.member != "" && t[i+1].op("("):
					out = append(out, modTok(b.mod, tk), Token{Kind: Op, Text: ".", Line: tk.Line}, Token{Kind: Ident, Text: b.member, Line: tk.Line})
					continue
				}
			}
		}
		out = append(out, tk)
	}
	return out
}

// declarations records the other declarations of the bound names, with their
// scopes: let, const and var (also in patterns) and function and class names up
// to the end of their block, and parameters up to the end of their function.
// The declaration that is itself a binding does not count.
func (m *modScope) declarations() {
	t, cl, at := m.t, m.cl, m.at
	decl := func(name string, from, to int) {
		if _, ok := m.binds[name]; !ok || m.tooMany[name] {
			return
		}
		for _, b := range m.binds[name] {
			if b.from == from {
				return // the binding itself
			}
		}
		if len(m.shadows[name]) >= maxScoped {
			m.tooMany[name] = true
			return
		}
		m.shadows[name] = append(m.shadows[name], scoped{from: from, to: to})
	}
	var pattern func(i, from, to int) int
	pattern = func(i, from, to int) int { // names bound by the pattern at i; returns the index after it
		switch {
		case at(i).Kind == Ident:
			decl(t[i].Text, from, to)
			return i + 1
		case at(i).op("{") || at(i).op("["):
			c := closeAt(cl, i)
			for k := i + 1; k < c && k < len(t); k++ {
				switch {
				case t[k].Kind == Ident && at(k+1).op(":") && at(i).op("{"):
					// a key: the name follows the ":"
				case t[k].Kind == Ident && (at(k-1).op("{") || at(k-1).op(",") || at(k-1).op("[") || at(k-1).op(":") || at(k-1).op("...")):
					decl(t[k].Text, from, to)
				}
			}
			return c + 1
		}
		return i + 1
	}
	// body returns the end of the function whose parameters end at c.
	body := func(c, def int) int {
		switch {
		case at(c + 1).op("{"):
			return closeAt(cl, c+1)
		case at(c+1).op("=>") && at(c+2).op("{"):
			return closeAt(cl, c+2)
		}
		return def
	}
	for i := 0; i < len(t); i++ {
		tk := t[i]
		member := i > 0 && memberOp(false, t[i-1])
		switch {
		case member:
		case tk.word("const") || tk.word("let") || tk.word("var"):
			pattern(i+1, i, m.enc[i])
		case (tk.word("function") || tk.word("class")) && at(i+1).Kind == Ident:
			decl(t[i+1].Text, i, m.enc[i])
		case tk.word("import"):
			for k := i + 1; k < len(t) && k-i < 256 && !t[k].word("from") && !t[k].op(";"); k++ {
				if t[k].Kind == Ident && (at(k+1).op(",") || at(k+1).op("}") || at(k+1).word("from")) && !t[k].word("type") {
					decl(t[k].Text, i, len(t))
				}
			}
		case tk.Kind == Ident && at(i+1).op("=>"):
			decl(tk.Text, i, body(i, m.enc[i])) // q => ...
		case tk.op("("):
			c := closeAt(cl, i)
			p := at(i - 1)
			if p.Kind == Ident && (ctlWords[p.Text] || p.Text == "switch") {
				continue // if (run): a use, not a parameter
			}
			if !(at(c+1).op("=>") || at(c+1).op("{") && (p.Kind == Ident || p.op(")"))) {
				continue
			}
			end := body(c, m.enc[i])
			for k := i + 1; k < c && k < len(t); k++ { // parameter names at the top of the list
				if (at(k-1).op("(") || at(k-1).op(",") || at(k-1).op("...")) && (t[k].Kind == Ident || t[k].op("{") || t[k].op("[")) {
					k = pattern(k, i, end) - 1
				} else if isOpen(t[k]) {
					k = closeAt(cl, k)
				}
			}
		}
	}
}

func closeAt(cl []int, i int) int {
	if i >= 0 && i < len(cl) {
		return cl[i]
	}
	return len(cl)
}
