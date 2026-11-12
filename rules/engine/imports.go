package engine

import "strings"

// importsLeaveOut reports whether a method sink's file imports one of the
// modules of unless_imports (JavaScript: import ... from 'm', import 'm',
// require('m'), also 'm/sub'), while neither the file nor the receiver names
// one of unless_imports_not (an identifier, or an imported module). A file
// the analysis has no tokens of (a callee analysed from another file's call)
// leaves nothing out.
func (a *analysis) importsLeaveOut(cond *argCond, recv []Token) bool {
	if a.ifacts == nil {
		if len(a.ftoks) == 0 {
			return false
		}
		a.ifacts = fileFacts(a.ftoks, nil)
	}
	in := false
	for _, m := range cond.unlessImports {
		in = in || a.ifacts["m:"+m]
	}
	if !in {
		return false
	}
	for _, w := range cond.importsNot {
		if a.ifacts["m:"+w] || a.ifacts["w:"+w] {
			return false
		}
		for _, t := range recv {
			if t.Kind == Ident && t.Text == w {
				return false
			}
		}
	}
	return true
}

// fileFacts returns what a JavaScript file imports ("m:" and the module; the
// package name of 'm/sub' too) and the identifiers it names ("w:" and the
// name), only those in watch when watch is given (what a project keeps of a
// file: the few some rule looks for).
func fileFacts(t []Token, watch map[string]bool) map[string]bool {
	out := map[string]bool{}
	add := func(k string) {
		if watch == nil || watch[k] {
			out[k] = true
		}
	}
	mod := func(s string) {
		add("m:" + s)
		if i := strings.Index(s, "/"); i > 0 && !strings.HasPrefix(s, "@") {
			add("m:" + s[:i])
		}
	}
	for i, tk := range t {
		switch {
		case tk.Kind == Ident:
			add("w:" + tk.Text)
		case tk.Kind == Str && len(tk.Parts) == 0 && i > 0 && (t[i-1].word("from") || t[i-1].word("import")):
			mod(tk.Text)
		case tk.Kind == Str && len(tk.Parts) == 0 && i > 1 && t[i-1].op("(") && t[i-2].word("require"):
			mod(tk.Text)
		}
	}
	return out
}

// importFacts is fileFacts for a file a project keeps: JavaScript only, and
// only what some rule's unless_imports looks for.
func (e *Engine) importFacts(lang string, toks []Token) map[string]bool {
	if lang != "js" || len(e.watch) == 0 {
		return nil
	}
	return fileFacts(toks, e.watch)
}

func (e *Engine) watchFor(k string) {
	if e.watch == nil {
		e.watch = map[string]bool{}
	}
	e.watch[k] = true
}
