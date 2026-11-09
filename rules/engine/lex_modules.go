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
	binds := map[string]modBinding{}
	cl := closers(toks)
	collectModuleBindings(toks, cl, binds)
	// A name declared again anywhere in the file (a local const, a parameter)
	// may not be the module there: scopes are not followed, so it is dropped.
	for name, n := range declarations(toks, cl) {
		if n > 1 {
			delete(binds, name)
		}
	}
	return rewriteModules(toks, binds)
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

func collectModuleBindings(t []Token, cl []int, binds map[string]modBinding) {
	at := func(i int) Token {
		if i >= 0 && i < len(t) {
			return t[i]
		}
		return Token{Kind: Op}
	}
	for i := 0; i < len(t); i++ {
		switch {
		case (t[i].word("const") || t[i].word("let") || t[i].word("var")) && at(i+1).Kind == Ident && at(i+2).op("="):
			// const fs = require('fs'), const fsp = require('fs').promises
			if m, j := requireAt(t, i+3); m != "" {
				if at(j).op(".") && at(j+1).Kind == Ident && !at(j+2).op("(") {
					binds[t[i+1].Text] = modBinding{mod: m, member: t[j+1].Text} // const run = require('child_process').exec
				} else {
					binds[t[i+1].Text] = modBinding{mod: m}
				}
			} else if b, ok := binds[at(i+3).Text]; ok && at(i+3).Kind == Ident && b.member == "" && !at(i+4).op(".") && !at(i+4).op("(") {
				binds[t[i+1].Text] = b // const c = cp0
			} else if m := moduleOf(at(i + 3).Text); m != "" && at(i+3).Kind == Ident && at(i+4).op(".") && at(i+5).word("promises") {
				binds[t[i+1].Text] = modBinding{mod: m} // const fsp = fs.promises
			}
		case (t[i].word("const") || t[i].word("let") || t[i].word("var")) && at(i+1).op("{"):
			// const { readFileSync: r, promises: fsp } = require('fs')
			c := closeAt(cl, i+1)
			if !at(c + 1).op("=") {
				continue
			}
			if m, _ := requireAt(t, c+2); m != "" {
				destructure(t[i+2:c], m, ":", binds)
			} else if b, ok := binds[at(c+2).Text]; ok && at(c+2).Kind == Ident && b.member == "" && !at(c+3).op(".") {
				destructure(t[i+2:c], b.mod, ":", binds) // const { exec: run } = cp0
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
			m := moduleOf(t[j+1].Text)
			if m == "" {
				continue
			}
			for k := i + 1; k < j; k++ {
				switch {
				case t[k].op("{"):
					c := min(closeAt(cl, k), j)
					destructure(t[k+1:c], m, "as", binds)
					k = c
				case t[k].op("*") && at(k+1).word("as") && at(k+2).Kind == Ident:
					binds[t[k+2].Text] = modBinding{mod: m}
					k += 2
				case t[k].Kind == Ident && !t[k].word("type") && (at(k+1).op(",") || at(k+1).word("from")):
					binds[t[k].Text] = modBinding{mod: m} // the default import
				}
			}
		}
	}
}

// destructure reads "a, b: c" (sep ":") or "a, b as c" (sep "as") from module m.
func destructure(t []Token, m, sep string, binds map[string]modBinding) {
	for _, part := range splitTop(t, isOp(",")) {
		if len(part) == 0 || part[0].Kind != Ident {
			continue
		}
		name, local := part[0].Text, part[0].Text
		if len(part) >= 3 && (sep == ":" && part[1].op(":") || sep == "as" && part[1].word("as")) && part[2].Kind == Ident {
			local = part[2].Text
		}
		if name == "promises" {
			binds[local] = modBinding{mod: m}
		} else {
			binds[local] = modBinding{mod: m, member: name}
		}
	}
}

func rewriteModules(t []Token, binds map[string]modBinding) []Token {
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
				parts[k] = Part{Off: p.Off, Toks: rewriteModules(p.Toks, binds)}
			}
			tk.Parts = parts
		}
		if m, j := requireAt(t, i); m != "" {
			out = append(out, modTok(m, tk))
			i = j - 1
			continue
		}
		if tk.Kind == Ident && !member && i+1 < len(t) {
			b, bound := binds[tk.Text]
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

// declarations counts, per name, the places a file declares it: let, const and
// var (also in patterns), function and class names, imports and parameters.
func declarations(t []Token, cl []int) map[string]int {
	n := map[string]int{}
	at := func(i int) Token {
		if i >= 0 && i < len(t) {
			return t[i]
		}
		return Token{Kind: Op}
	}
	var pattern func(i int) int
	pattern = func(i int) int { // names bound by the pattern at i; returns the index after it
		switch {
		case at(i).Kind == Ident:
			n[t[i].Text]++
			return i + 1
		case at(i).op("{") || at(i).op("["):
			c := closeAt(cl, i)
			for k := i + 1; k < c && k < len(t); k++ {
				switch {
				case t[k].Kind == Ident && at(k+1).op(":") && at(i).op("{"):
					// a key: the name follows the ":"
				case t[k].Kind == Ident && (at(k-1).op("{") || at(k-1).op(",") || at(k-1).op("[") || at(k-1).op(":") || at(k-1).op("...")):
					n[t[k].Text]++
				}
			}
			return c + 1
		}
		return i + 1
	}
	for i := 0; i < len(t); i++ {
		tk := t[i]
		member := i > 0 && memberOp(false, t[i-1])
		switch {
		case member:
		case tk.word("const") || tk.word("let") || tk.word("var"):
			pattern(i + 1)
		case (tk.word("function") || tk.word("class")) && at(i+1).Kind == Ident:
			n[t[i+1].Text]++
		case tk.word("import"):
			for k := i + 1; k < len(t) && k-i < 256 && !t[k].word("from") && !t[k].op(";"); k++ {
				if t[k].Kind == Ident && (at(k+1).op(",") || at(k+1).op("}") || at(k+1).word("from")) && !t[k].word("type") {
					n[t[k].Text]++
				}
			}
		case tk.Kind == Ident && at(i+1).op("=>"):
			n[tk.Text]++ // q => ...
		case tk.op("("):
			c := closeAt(cl, i)
			if !(at(c+1).op("=>") || at(c+1).op("{") && (at(i-1).Kind == Ident || at(i-1).op(")"))) {
				continue
			}
			for k := i + 1; k < c && k < len(t); k++ { // parameter names at the top of the list
				if (at(k-1).op("(") || at(k-1).op(",") || at(k-1).op("...")) && (t[k].Kind == Ident || t[k].op("{") || t[k].op("[")) {
					k = pattern(k) - 1
				} else if isOpen(t[k]) {
					k = closeAt(cl, k)
				}
			}
		}
	}
	return n
}

func closeAt(cl []int, i int) int {
	if i >= 0 && i < len(cl) {
		return cl[i]
	}
	return len(cl)
}
