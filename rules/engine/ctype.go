package engine

import "strings"

// ctypeKey marks, in a state, the Content-Type a JavaScript handler set on
// every path to here (san: merge keeps a key only when both paths have it).
const ctypeKey = "\x00ctype:"

// contentTypeStmt records a statement setting the response's Content-Type to
// a literal: res.setHeader("Content-Type", "text/event-stream"), res.set(...),
// res.header(...), res.type("text/event-stream"), res.contentType(...),
// res.writeHead(200, {"Content-Type": ...}) and res.set({...}). Only a statement that is that call or
// assignment (in a branch it holds on that path only; req.accepts(...) and a
// ternary set nothing), and only for rules with unless_content_type.
func (a *analysis) contentTypeStmt(st state, t []Token) {
	if !a.js || !a.r.ctypes || len(t) < 4 {
		return
	}
	if t[len(t)-1].op(";") {
		t = t[:len(t)-1]
	}
	if t[0].Kind != Ident && !t[0].word("this") {
		return
	}
	// the statement is one call: recv.method(args)
	open := -1
	for i := 1; i+1 < len(t); i++ {
		if t[i].op(".") && t[i+1].Kind == Ident && i+2 < len(t) && t[i+2].op("(") {
			open = i + 2
		}
	}
	if open < 0 || closeOf(t, open) != len(t)-1 {
		return
	}
	args := splitTop(inside(t, open, len(t)-1), isComma)
	str := func(x []Token) (string, bool) {
		if len(x) == 1 && x[0].Kind == Str && len(x[0].Parts) == 0 {
			return x[0].Text, true
		}
		return "", false
	}
	isCT := func(x []Token) bool { s, ok := str(x); return ok && strings.EqualFold(s, "content-type") }
	fromObject := func(x []Token) {
		if len(x) < 2 || !x[0].op("{") || closeOf(x, 0) != len(x)-1 {
			return
		}
		for _, el := range splitTop(x[1:len(x)-1], isComma) {
			if k := indexTop(el, 0, isOp(":")); k > 0 && (isCT(el[:k]) || len(el[:k]) == 1 && strings.EqualFold(el[0].Text, "content-type")) {
				if v, ok := str(el[k+1:]); ok {
					markContentType(st, v)
				}
			}
		}
	}
	switch t[open-1].Text {
	case "setHeader", "set", "header", "append":
		if len(args) == 2 && isCT(args[0]) {
			if v, ok := str(args[1]); ok {
				markContentType(st, v)
			}
		} else if len(args) == 1 {
			fromObject(args[0])
		}
	case "type", "contentType":
		if len(args) == 1 {
			if v, ok := str(args[0]); ok {
				markContentType(st, v)
			}
		}
	case "writeHead":
		for _, x := range args[min(1, len(args)):] {
			fromObject(x)
		}
	}
}

func markContentType(st state, v string) {
	mime, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(v)), ";")
	st[ctypeKey+strings.TrimSpace(mime)] = entry{san: true}
}

// contentTypeSet reports whether one of the types (lower case) was set on
// every path to here.
func contentTypeSet(st state, types []string) bool {
	for _, ct := range types {
		if e, ok := st[ctypeKey+ct]; ok && e.san {
			return true
		}
	}
	return false
}
