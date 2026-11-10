package engine

import (
	"maps"
	"slices"
	"strings"
)

// The analysis walks one function at a time, statement by statement, in order. It
// keeps a state: which variables (and member or index paths such as $user->lang)
// hold user input. Two layers share the walk:
//
//   - layer A: a sink whose dangerous argument contains a source, not wrapped in
//     one of the rule's sanitizers, is reported;
//   - layer B: an assignment from a tainted value taints the variable; taint
//     flows through concatenation, interpolation, calls, array and member access;
//     a sanitizer's result is clean; a check that rejects or replaces a value
//     (an allowlist, a type check, a path containment check) makes it clean on
//     the paths where the check holds. A sink reached by a tainted variable is
//     reported.
//
// Closures see the variables of the code around them; calls to other functions
// of the same file go through summaries (interproc.go).

const sepCh = "\x1f" // separates the parts of a path key: "$user" sepCh ".lang"

type entry struct {
	taint bool
	src   bool // the key is a source expression a check made clean (req.body.email)
	sep   bool // the value ends with a path separator ($base = realpath(...) . DIRECTORY_SEPARATOR)
	san   bool // the value was made by a sanitizer (env = SandboxedEnvironment())
	pre   bool // the value starts with a fixed part ($p = WP_PLUGIN_DIR . '/' . $name)
	raw   bool // the value came from input, even through a sanitizer ($n = basename($_GET['n']))
	emb   bool // the input is embedded in a larger string ("WHERE id = " . $id), not passed as is
	weak  bool // all the input came through the result of a call the analysis does not know (get_post($id))
}

type state map[string]entry

func (s state) clone() state {
	c := make(state, len(s))
	for k, v := range s {
		c[k] = v
	}
	return c
}

// get returns the entry of key or of its longest stored prefix.
func (s state) get(key string) (entry, bool) {
	for k := key; k != ""; {
		if e, ok := s[k]; ok {
			return e, true
		}
		i := strings.LastIndex(k, sepCh)
		if i < 0 {
			break
		}
		k = k[:i]
	}
	return entry{}, false
}

// del removes key and every path under it.
func (s state) del(key string) {
	for k := range s {
		if k == key || strings.HasPrefix(k, key+sepCh) {
			delete(s, k)
		}
	}
}

// merge joins the states of two paths: tainted on either path is tainted.
func merge(x, y state) state {
	out := make(state, len(x)+len(y))
	look := func(s state, k string, src bool) entry {
		if e, ok := s.get(k); ok {
			return e
		}
		return entry{taint: src, src: src, raw: src}
	}
	both := func(a, b entry) entry {
		return entry{taint: a.taint || b.taint, src: a.src || b.src, sep: a.sep && b.sep, san: a.san && b.san, pre: a.pre && b.pre,
			raw: a.raw || b.raw, emb: a.emb || b.emb, weak: weakOf(a.taint, a.weak, b.taint, b.weak)}
	}
	for k, e := range x {
		out[k] = both(e, look(y, k, e.src))
	}
	for k, e := range y {
		if _, ok := x[k]; !ok {
			out[k] = both(look(x, k, e.src), e)
		}
	}
	return out
}

type val struct{ taint, san, pre, raw, emb, weak bool } // pre, raw: see entry; set by assign only

// weakOf is the weak flag of a value with two tainted-or-not parts: weak when
// some part is tainted and every tainted part is weak.
func weakOf(t1, w1, t2, w2 bool) bool { return (t1 || t2) && (!t1 || w1) && (!t2 || w2) }

const (
	noExit    uint8 = iota
	breakExit       // break: ends a switch case or a loop
	softExit        // continue
	hardExit        // return, throw, exit, abort()
)

type analysis struct {
	r      *crule
	php    bool
	py     bool
	js     bool
	b      *budget
	kw     map[string]bool // words that are keywords in this language
	seen   map[loc]bool
	lines  []loc
	guards []map[string]bool // per enclosing loop: keys a rejecting check validated
	depth  int
	nested int  // functions defined inside the one analysed: their returns are not its returns
	raw    bool // evaluating whether a value came from input at all: sanitizers do not clean

	sc      *summaries // this rule's function summaries for the file (interproc.go)
	summ    *summRun   // set while a function body is analysed for its summary
	lib     bool       // library mode: public parameters are input, and only embedded input is reported
	nest    int        // summaries worked out inside one another to here (own)
	heights *int       // the highest summary used by the summary being worked out (own)

	noSrc  bool   // the rule's sources are off (a summary run for parameters)
	cls    string // class of the method being analysed, and its parent
	parent string
	fname  string // name of the function being analysed

	file  string            // the file analysed, for findings and for calls into other files
	proj  *Project          // the project the file belongs to, or nil (project.go)
	types map[string]string // variable → class of the object assigned to it ($x = new Foo)
}

// loc is a place a sink is reached: a line of a file.
type loc struct {
	path string
	line int
}

func (a *analysis) report(line int) { a.reportSink(loc{a.file, line}, false) }

// reportSink reports a sink reached at line; emb tells whether the input was
// embedded in a larger string, which a summary keeps for library mode.
func (a *analysis) reportSink(l loc, emb bool) {
	if a.summ != nil {
		a.summ.lines[l] = true
		if emb {
			a.summ.emb[l] = true
		}
		return
	}
	if !a.seen[l] {
		a.seen[l] = true
		a.lines = append(a.lines, l)
	}
}

// ---- statements ----

func (a *analysis) block(ss []*stmt, st state) (state, uint8) {
	for _, s := range ss {
		if !a.b.step() {
			return st, noExit
		}
		var e uint8
		st, e = a.stmt(s, st)
		if e != noExit {
			return st, e
		}
	}
	return st, noExit
}

func (a *analysis) stmt(s *stmt, st state) (state, uint8) {
	for _, f := range s.funcs {
		a.function(f, st)
	}
	switch s.kind {
	case sSimple:
		a.sinks(st, s.toks)
		if a.summ != nil && len(s.toks) > 0 && s.toks[0].word("return") {
			a.summ.ret = or(a.summ.ret, a.expr(st, s.toks[1:], false))
			// What a return that can be true checks: values that still held a
			// parameter's input there ($c = 'id'; return in_array($c, ...) checks
			// nothing passed in). A closure's return is not one of these.
			if rest := s.toks[1:]; a.nested == 0 && !(len(rest) == 1 && falsy(rest)) {
				set := map[string]bool{}
				if _, cleaned := a.refine(st, rest, true); len(cleaned) > 0 {
					for _, k := range cleaned {
						if st[k].taint {
							set[k] = true
						}
					}
				}
				a.summ.checks = append(a.summ.checks, set)
			}
		}
		a.assignStmt(st, s.toks)
		a.assertStmt(st, s.toks)
		return st, a.exitOf(s.toks)
	case sIf:
		a.sinks(st, s.toks)
		t1, _ := a.refine(st, s.toks, true)
		t1, e1 := a.block(s.body, t1)
		t2, g2 := a.refine(st, s.toks, false)
		e2 := noExit
		if len(s.els) > 0 {
			t2, e2 = a.block(s.els, t2)
		}
		if e1 == hardExit && len(a.guards) > 0 {
			for _, k := range g2 {
				a.guards[len(a.guards)-1][k] = true
			}
		}
		switch {
		case e1 != noExit && e2 != noExit:
			return t1, min(e1, e2)
		case e1 != noExit:
			return t2, noExit
		case e2 != noExit:
			return t1, noExit
		}
		return merge(t1, t2), noExit
	case sLoop:
		return a.loop(s, st), noExit
	case sWith:
		for _, item := range splitTop(s.toks, isComma) {
			x, tg := item, []Token(nil)
			if i := indexTop(item, 0, isWord("as")); i > 0 {
				x, tg = item[:i], item[i+1:]
			}
			a.sinks(st, x)
			v := a.expr(st, x, false)
			for _, t := range a.targetList(tg) {
				a.setTarget(st, t, v, "=", false)
			}
		}
		return a.block(s.body, st)
	case sBlock:
		a.sinks(st, s.toks)
		if s.alt {
			t, e := a.block(s.body, st.clone())
			if e != noExit {
				return st, noExit
			}
			return merge(st, t), noExit
		}
		return a.block(s.body, st)
	case sTry:
		return a.try(s, st)
	case sSwitch:
		return a.switchStmt(s, st)
	case sFunc:
		if a.summ == nil || s.fn == nil || s.fn.name == "" { // named functions have summaries of their own
			a.function(s.fn, st)
		}
	}
	return st, noExit
}

// try: the body may stop at any statement, so a handler starts from what the
// state was before or after it; the code after continues from every path that
// did not exit.
func (a *analysis) try(s *stmt, st state) (state, uint8) {
	s1, e1 := a.block(s.body, st.clone())
	if e1 == noExit && len(s.orelse) > 0 {
		s1, e1 = a.block(s.orelse, s1)
	}
	from := merge(st, s1)
	var outs []state
	exit := hardExit
	if e1 == noExit {
		outs = append(outs, s1)
	} else {
		exit = min(exit, e1)
	}
	for _, h := range s.handlers {
		sh, eh := a.block(h, from.clone())
		if eh == noExit {
			outs = append(outs, sh)
		} else {
			exit = min(exit, eh)
		}
	}
	out, e := mergeAll(outs), noExit
	if out == nil {
		out, e = from, exit
	}
	if len(s.els) > 0 {
		var ef uint8
		if out, ef = a.block(s.els, out); ef != noExit {
			return out, ef
		}
	}
	return out, e
}

// switchStmt: each case is entered from the state before the switch or by
// falling through from the case above it, in one pass.
func (a *analysis) switchStmt(s *stmt, st state) (state, uint8) {
	a.sinks(st, s.toks)
	var outs []state
	var fall state // state falling into the next case, nil when the case above exited
	exit := hardExit
	for _, c := range s.cases {
		in := st.clone()
		if fall != nil {
			in = merge(st, fall)
		}
		x, e := a.block(c, in)
		fall = nil
		switch e {
		case noExit:
			fall = x
		case breakExit:
			outs = append(outs, x)
		default:
			exit = min(exit, e)
		}
	}
	if fall != nil {
		outs = append(outs, fall)
	}
	if !s.hasDefault {
		outs = append(outs, st)
	}
	if out := mergeAll(outs); out != nil {
		return out, noExit
	}
	return st, exit
}

func mergeAll(ss []state) state {
	if len(ss) == 0 {
		return nil
	}
	out := ss[0]
	for _, x := range ss[1:] {
		out = merge(out, x)
	}
	return out
}

func (a *analysis) function(f *fn, st state) {
	if f == nil {
		return
	}
	if a.depth > maxNest {
		a.b.tooDeep() // too deeply nested to follow
		return
	}
	x := state{}
	if !f.fresh {
		x = st.clone()
	}
	for _, p := range f.params {
		if p.Kind == Var || p.Kind == Ident {
			x.del(p.Text)
		}
	}
	a.libParams(f, x)
	cls, parent, fname, types := a.cls, a.parent, a.fname, a.types
	if f.method {
		a.cls, a.parent = f.class, f.parent
	}
	if f.name != "" {
		a.fname = f.name
	}
	if f.fresh || f.name != "" {
		a.types = map[string]string{}
	} else {
		a.types = maps.Clone(types)
	}
	a.paramTypes(f)
	defer func() { a.cls, a.parent, a.fname, a.types = cls, parent, fname, types }()
	a.depth++
	a.nested++
	a.block(f.body, x)
	a.nested--
	a.depth--
}

func (a *analysis) loop(s *stmt, st state) state {
	body := s.body
	var targets, iter, cond []Token
	switch s.loop {
	case "for":
		parts := splitTop(s.toks, isSemi)
		a.sinks(st, s.toks)
		a.assignStmt(st, parts[0])
		if len(parts) > 1 {
			cond = parts[1]
		}
		if len(parts) > 2 && len(parts[2]) > 0 {
			body = append(append([]*stmt(nil), body...), &stmt{kind: sSimple, toks: parts[2]})
		}
	case "each":
		if i := indexTop(s.toks, 0, isWord("as")); i > 0 {
			iter = s.toks[:i]
			for _, side := range splitTop(s.toks[i+1:], isOp("=>")) {
				targets = append(targets, side...)
				targets = append(targets, Token{Kind: Op, Text: ","})
			}
		}
	case "in":
		h := s.toks
		for len(h) > 0 && h[0].Kind == Ident && (declWords[h[0].Text] || h[0].Text == "await") {
			h = h[1:]
		}
		in := indexTop(h, 0, func(t Token) bool { return t.word("in") || !a.py && t.word("of") })
		if in > 0 {
			targets, iter = h[:in], h[in+1:]
		}
	case "while":
		a.sinks(st, s.toks)
		cond = s.toks
	}
	var iv val
	if iter != nil {
		a.sinks(st, iter)
		iv = a.expr(st, iter, false)
	}
	tl := a.targetList(targets)
	bind := func(x state) {
		for _, t := range tl {
			a.setTarget(x, t, iv, "=", false)
		}
	}
	enter := func(x state) state {
		if cond != nil {
			x, _ = a.refine(x, cond, true)
			return x
		}
		return x.clone()
	}
	bind(st)
	a.guards = append(a.guards, map[string]bool{})
	s1, _ := a.block(body, enter(st))
	m := merge(st, s1)
	bind(m)
	s2, _ := a.block(body, enter(m))
	out := merge(m, s2)
	checked := a.guards[len(a.guards)-1]
	a.guards = a.guards[:len(a.guards)-1]
	// Every member was checked and a bad one rejects the whole input (raise,
	// return), so the collection itself is validated after the loop.
	if root := a.rootKey(iter); root != "" {
		for _, t := range tl {
			if k, _, ok := a.pathKey(t); ok && checked[k] {
				out[root] = entry{}
			}
		}
	}
	return out
}

var declWords = map[string]bool{"const": true, "let": true, "var": true, "global": true, "static": true,
	"public": true, "private": true, "protected": true, "readonly": true, "final": true}

var exitCalls = map[string]bool{"abort": true, "wp_die": true, "exit": true, "die": true}

func (a *analysis) exitOf(t []Token) uint8 {
	if len(t) == 0 || t[0].Kind != Ident {
		return noExit
	}
	switch t[0].Text {
	case "return", "throw", "raise":
		return hardExit
	case "break":
		return breakExit
	case "continue":
		return softExit
	case "exit", "die":
		if a.php {
			return hardExit
		}
	}
	if len(t) > 1 && t[1].op("(") && exitCalls[t[0].Text] {
		return hardExit
	}
	if len(t) > 3 && (t[0].Text == "sys" || t[0].Text == "process") && t[1].op(".") && t[2].word("exit") {
		return hardExit
	}
	return noExit
}

// ---- assignments ----

func isAssignOp(t Token) bool {
	if t.Kind != Op {
		return false
	}
	switch t.Text {
	case "=", ".=", "+=", "-=", "*=", "/=", "%=", "??=", "||=", "&&=", "|=", "&=", "^=", "**=", "<<=", ">>=", ":=":
		return true
	}
	return false
}

func (a *analysis) assignStmt(st state, t []Token) {
	decl := false
	for len(t) > 0 && t[0].Kind == Ident && declWords[t[0].Text] {
		t, decl = t[1:], true
	}
	if a.php {
		// $x = $_GET['a'] or die(); assigns $_GET['a']: "or", "and", "xor" bind looser than "=".
		t = splitTop(t, func(x Token) bool { return x.word("or") || x.word("and") || x.word("xor") })[0]
	}
	if a.js && decl {
		for _, d := range splitTop(t, isComma) {
			a.assign(st, d)
		}
		return
	}
	a.assign(st, t)
}

func (a *analysis) assign(st state, t []Token) (val, bool) {
	k := indexTop(t, 0, isAssignOp)
	if k <= 0 {
		return val{}, false
	}
	lhs, rhs := t[:k], t[k+1:]
	if a.py {
		if c := indexTop(lhs, 0, isOp(":")); c > 0 {
			lhs = lhs[:c]
		}
	}
	var v val
	var sep bool
	if indexTop(rhs, 0, isAssignOp) > 0 {
		v, sep = a.assign(st, rhs)
	} else {
		v, sep = a.expr(st, rhs, false), a.sepEnd(st, rhs)
		if a.r.leading { // only a leading condition reads these
			v.pre = a.fixedStart(st, rhs)
			v.raw = v.taint || a.rawInput(st, rhs)
		}
	}
	cls := a.newClass(rhs)
	for _, tg := range a.targetList(lhs) {
		a.setTarget(st, tg, v, t[k].Text, sep)
		if cls != "" && len(tg) == 1 {
			a.setType(tg[0].Text, cls)
		}
	}
	return v, sep
}

// newClass returns the class an expression makes: new Foo(...), Python Foo(...).
func (a *analysis) newClass(t []Token) string {
	switch {
	case len(t) > 1 && !a.py && t[0].word("new") && (t[1].Kind == Ident || t[1].op(`\`)):
		return strings.TrimPrefix(qualifiedName(t, 1), `\`)
	case len(t) > 2 && a.py && t[0].Kind == Ident && t[1].op("(") && closeOf(t, 1) == len(t)-1 && t[0].Text[0] >= 'A' && t[0].Text[0] <= 'Z':
		return t[0].Text
	}
	return ""
}

func (a *analysis) setType(name, cls string) {
	if a.types == nil {
		a.types = map[string]string{}
	}
	a.types[name] = cls
}

// paramTypes records parameters declared with a class type (Foo $x, x: Foo).
func (a *analysis) paramTypes(f *fn) {
	for _, part := range splitTop(f.params, isComma) {
		for k := 0; k+1 < len(part); k++ {
			switch {
			case a.php && part[k].Kind == Ident && part[k+1].Kind == Var && !numericCasts[strings.ToLower(part[k].Text)] &&
				!scalarTypes[strings.ToLower(part[k].Text)]:
				a.setType(part[k+1].Text, part[k].Text)
			case a.py && k == 0 && len(part) > 2 && part[0].Kind == Ident && part[1].op(":") && part[2].Kind == Ident:
				a.setType(part[0].Text, part[2].Text)
			}
		}
	}
}

var scalarTypes = words("string array mixed callable iterable object self static void null")

// targetList splits an assignment target into the paths it writes: a, [a, b],
// {a, b: c}, list($a, $b), "k, v" in Python.
func (a *analysis) targetList(lhs []Token) [][]Token {
	for len(lhs) > 0 && (lhs[0].Kind == Ident && declWords[lhs[0].Text] || lhs[0].op("&") || lhs[0].op("...") || lhs[0].op("*")) {
		lhs = lhs[1:]
	}
	if len(lhs) == 0 {
		return nil
	}
	if parts := splitTop(lhs, isComma); len(parts) > 1 {
		var out [][]Token
		for _, p := range parts {
			out = append(out, a.targetList(p)...)
		}
		return out
	}
	inner := []Token(nil)
	switch {
	case len(lhs) >= 2 && isOpen(lhs[0]) && closeOf(lhs, 0) == len(lhs)-1:
		inner = lhs[1 : len(lhs)-1]
	case a.php && len(lhs) > 2 && (lhs[0].word("list") || lhs[0].word("array")) && lhs[1].op("(") && closeOf(lhs, 1) == len(lhs)-1:
		inner = lhs[2 : len(lhs)-1]
	default:
		return [][]Token{lhs[a.chainStart(lhs, len(lhs)):]}
	}
	var out [][]Token
	for _, e := range splitTop(inner, isComma) {
		if i := indexTop(e, 0, isOp("=>")); i >= 0 {
			e = e[i+1:]
		} else if i := indexTop(e, 0, isOp(":")); i >= 0 && lhs[0].op("{") {
			e = e[i+1:]
		}
		if i := indexTop(e, 0, isOp("=")); i > 0 {
			e = e[:i]
		}
		out = append(out, a.targetList(e)...)
	}
	return out
}

func (a *analysis) setTarget(st state, tg []Token, v val, op string, sep bool) {
	key, container, ok := a.pathKey(tg)
	if !ok {
		return
	}
	if container != "" {
		e, _ := st.get(container)
		st[container] = entry{taint: e.taint || v.taint, raw: e.raw || v.raw, emb: e.emb || v.emb, weak: weakOf(e.taint, e.weak, v.taint, v.weak)}
		if strings.HasSuffix(key, "[*]") && v.taint {
			st.del(container) // $a[$i] = input may overwrite any key: forget what was known per key
			st[container] = entry{taint: true, raw: true, emb: v.emb, weak: v.weak}
		}
		if !strings.HasSuffix(key, "[*]") {
			// $args['limit'] = absint(...): the key itself is known; reading another key
			// or the whole array still sees the container.
			if op == "=" {
				st.del(key)
				st[key] = entry{taint: v.taint, san: v.san, sep: sep, pre: v.pre, raw: v.raw, emb: v.emb, weak: v.weak}
			} else {
				ek, _ := st.get(key) // $q['w'] .= $input taints the key it appends to
				st[key] = entry{taint: ek.taint || v.taint, sep: sep, pre: ek.pre, raw: ek.raw || v.raw, emb: ek.emb || v.taint,
					weak: weakOf(ek.taint, ek.weak, v.taint, v.weak)}
			}
		}
		return
	}
	if op == "=" || op == ":=" {
		st.del(key)
		st[key] = entry{taint: v.taint, san: v.san, sep: sep, pre: v.pre, raw: v.raw, emb: v.emb, weak: v.weak}
		return
	}
	e, _ := st.get(key)
	st[key] = entry{taint: e.taint || v.taint, sep: sep, pre: e.pre, raw: e.raw || v.raw, emb: e.emb || v.taint,
		weak: weakOf(e.taint, e.weak, v.taint, v.weak)} // appending keeps the start
}

// pathKey returns the key of a plain path ($x, $x->a, x.y, x["k"]). When the path
// ends with an index, container is the key of what is indexed: writing $a[] = $x
// taints $a.
func (a *analysis) pathKey(t []Token) (key, container string, ok bool) {
	if len(t) == 0 || t[0].Kind != Var && t[0].Kind != Ident || a.kw[t[0].Text] {
		return "", "", false
	}
	key = t[0].Text
	for j := 1; j < len(t); {
		switch {
		case memberOp(a.php, t[j]) && j+1 < len(t) && (t[j+1].Kind == Ident || t[j+1].Kind == Var):
			key += sepCh + "." + t[j+1].Text
			container = ""
			j += 2
		case t[j].op("["):
			c := closeOf(t, j)
			container = key
			key += sepCh + "[" + idxKey(inside(t, j, c)) + "]"
			j = c + 1
		default:
			return "", "", false
		}
	}
	return key, container, true
}

func idxKey(t []Token) string {
	if len(t) == 1 && (t[0].Kind == Str || t[0].Kind == Num) && len(t[0].Parts) == 0 {
		return t[0].Text
	}
	return "*"
}

// rootKey is the variable an expression such as zf.namelist() starts from.
func (a *analysis) rootKey(t []Token) string {
	if len(t) > 0 && (t[0].Kind == Var || t[0].Kind == Ident) && !a.kw[t[0].Text] {
		return t[0].Text
	}
	return ""
}

// chainStart walks back from end over a postfix chain (a->b()[c].d) and returns
// where it starts.
func (a *analysis) chainStart(t []Token, end int) int {
	j := end
	for j > 0 {
		p := t[j-1]
		switch {
		case isClose(p):
			j = openOf(t, j-1)
			if j == 0 {
				return 0
			}
			q := t[j-1]
			if !(q.Kind == Ident && !a.kw[q.Text] || q.Kind == Var || isClose(q) || memberOp(a.php, q)) {
				return j
			}
		case memberOp(a.php, p):
			j--
		case p.Kind == Ident && !a.kw[p.Text] || p.Kind == Var || p.Kind == Str || p.Kind == Num:
			j--
			if j == 0 || !memberOp(a.php, t[j-1]) {
				return j
			}
		default:
			return j
		}
	}
	return j
}

// sepEnd reports whether a value ends with a path separator, so a prefix check
// against it cannot be passed by a sibling folder (/var/www/assets-private).
func (a *analysis) sepEnd(st state, rhs []Token) bool {
	join := "+"
	if a.php {
		join = "."
	}
	parts := splitTop(rhs, isOp(join))
	last := parts[len(parts)-1]
	if len(last) == 0 {
		return false
	}
	if len(last) == 1 && last[0].Kind == Str && len(last[0].Parts) == 0 {
		return strings.HasSuffix(last[0].Text, "/") || strings.HasSuffix(last[0].Text, "\\")
	}
	key, _, ok := a.pathKey(last)
	if !ok {
		return false
	}
	switch strings.ReplaceAll(key, sepCh, "") {
	case "DIRECTORY_SEPARATOR", "path.sep", "os.sep", "os.path.sep":
		return true
	}
	e, _ := st.get(key)
	return e.sep
}

// fixedStart reports whether a value begins with a part the client cannot
// control and that names no stream: a non-empty literal without ":", a constant,
// both branches of a ternary that do, a variable assigned one, a property or array
// key the input never reached ($this->dir, $u['basedir']), or a call whose
// arguments are all clean (dirname(__FILE__), get_template_directory()). A call
// on input (basename($_GET['d'])) is no prefix. Input behind a fixed prefix
// cannot choose a wrapper (phar://). A clean call that returns "" (trim(' '))
// is a known miss.
func (a *analysis) fixedStart(st state, t []Token) bool {
	if !a.b.charge(len(t) + 1) {
		return false
	}
	join := "+"
	if a.php {
		join = "."
	}
	parts := splitTop(t, isOp(join))
	// Literals at the start ('tpl' . '/' . $x, "ph$x") read as one text.
	lit, k := "", 0
	for ; k < len(parts) && len(parts[k]) == 1 && parts[k][0].Kind == Str; k++ {
		tk := parts[k][0]
		if len(tk.Parts) > 0 {
			lit += tk.Text[:min(tk.Parts[0].Off, len(tk.Text))]
			k++
			break
		}
		lit += tk.Text
	}
	if k > 0 {
		return notScheme(lit)
	}
	first := parts[0]
	n := len(first)
	if n > 2 && first[0].op("(") && closeOf(first, 0) == n-1 {
		inner := first[1 : n-1]
		if q := indexTop(inner, 0, isOp("?")); q >= 0 {
			if c := ternaryColon(inner, q); c > q+1 {
				return a.fixedStart(st, inner[q+1:c]) && a.fixedStart(st, inner[c+1:])
			}
			return false
		}
		return a.fixedStart(st, inner)
	}
	switch {
	case a.php && n == 1 && first[0].Kind == Ident && !a.kw[first[0].Text] && !isLiteral(first):
		return true // a constant: WP_PLUGIN_DIR, __DIR__ (in PHP a bare name is no variable)
	case a.php && n == 3 && first[0].Kind == Ident && first[1].op("::") && first[2].Kind == Ident:
		return true // a class constant: self::BASE
	}
	if key, _, ok := a.pathKey(first); ok {
		if e, found := st.get(key); found {
			return e.pre
		}
		// A property or key that was never assigned here; a plain variable may be "".
		// Superglobals and request objects are input whether or not this rule lists them.
		if n == 4 && first[0].Text == "$_SERVER" && first[2].Kind == Str && first[2].Text == "DOCUMENT_ROOT" {
			return true // set by the server, an absolute path
		}
		return n > 1 && !requestRoot(first[0].Text) && !a.rawInput(st, first)
	}
	if n > 2 && first[n-1].op(")") && a.chainStart(first, n) == 0 {
		if a.php && first[0].Kind == Ident && first[1].op("(") {
			args := splitTop(inside(first, 1, n-1), isComma)
			switch first[0].Text {
			case "storage_path", "base_path", "public_path", "resource_path", "app_path", "database_path", "config_path":
				return true // Laravel: the app's own folder, then the argument
			case "sprintf":
				if len(args) > 0 && len(args[0]) == 1 && args[0][0].Kind == Str && len(args[0][0].Parts) == 0 {
					head, _, _ := strings.Cut(args[0][0].Text, "%")
					return notScheme(head)
				}
			}
			if n == closeOf(first, 1)+1 {
				// The arguments, not the result, and before any sanitizer: basename($_GET['d'])
				// is a clean name but may be "phar". Numbers (intval) carry nothing.
				for _, arg := range args {
					if a.rawInput(st, arg) || len(arg) > 0 && requestRoot(arg[0].Text) {
						return false
					}
				}
				return true
			}
		}
		return !a.rawInput(st, first) && !requestRoot(first[0].Text)
	}
	return false
}

// rawInput reports whether t holds input, also when a sanitizer wrapped it.
func (a *analysis) rawInput(st state, t []Token) bool {
	if a.raw {
		return a.expr(st, t, false).taint
	}
	a.raw = true
	defer func() { a.raw = false }()
	return a.expr(st, t, false).taint
}

// requestRoot reports whether a path starts at a PHP superglobal or a request object.
func requestRoot(name string) bool {
	return strings.HasPrefix(name, "$_") || name == "$GLOBALS" || name == "$request" || name == "request"
}

// notScheme reports whether text, put before any input, keeps the result from
// being a URL: it holds a character a scheme cannot ("/", "_", " ") before any
// ":". "phar" or "ph" can be completed into "phar://" by the input; "tpl/" cannot.
func notScheme(text string) bool {
	for i := 0; i < len(text); i++ {
		c := text[i]
		if isAlnum(c) || c == '+' || c == '-' || c == '.' {
			continue
		}
		return c != ':'
	}
	return false
}

// ---- expressions ----

// keywords are words that are keywords or operators in each language; they are
// skipped when reading an expression and never start a path. Anything else may be
// a variable name: fn, use, echo or from are ordinary names in Python and JS.
var keywords = map[string]map[string]bool{
	"php": words("return throw yield new clone echo print include include_once require require_once and or xor " +
		"instanceof function fn use global const case if else elseif as insteadof"),
	"python": words("return yield await raise in not and or is lambda if else elif del pass global nonlocal " +
		"from import as async def class with for while try except finally assert"),
	"js": words("return throw yield await new delete void typeof in instanceof function case const let var " +
		"if else do while for switch try catch finally class extends"),
}

func words(list string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(list) {
		m[w] = true
	}
	return m
}

func isWord(w string) func(Token) bool { return func(t Token) bool { return t.word(w) } }
func isOp(o string) func(Token) bool   { return func(t Token) bool { return t.op(o) } }

func (a *analysis) isCompare(t Token) bool {
	switch t.Kind {
	case Op:
		switch t.Text {
		case "==", "===", "!=", "!==", "<", ">", "<=", ">=", "<>", "<=>":
			return true
		}
	case Ident:
		switch t.Text {
		case "instanceof":
			return true
		case "in":
			return !a.php
		case "is", "not":
			return a.py
		}
	}
	return false
}

func stripParens(t []Token) []Token {
	for len(t) >= 2 && t[0].op("(") && closeOf(t, 0) == len(t)-1 {
		t = t[1 : len(t)-1]
	}
	return t
}

// expr evaluates the taint of an expression. whole asks whether the value itself
// is user input, not merely an object or array literal holding some.
func (a *analysis) expr(st state, t []Token, whole bool) val {
	if len(t) == 0 {
		return val{}
	}
	// An expression is scanned about eight times over (conditions, operators,
	// terms), so it is charged that much: a hostile file cannot outrun the clock.
	if !a.b.charge(8*len(t) + 1) {
		return val{}
	}
	if a.depth > 4*maxNest {
		a.b.tooDeep() // too deep to read: assume the worst
		return val{taint: true}
	}
	a.depth++
	defer func() { a.depth-- }()

	// Conditional expressions: each branch under its condition.
	if a.py {
		if t[0].word("lambda") {
			return val{}
		}
		if f := indexTop(t, 0, isWord("for")); f > 0 {
			return a.comprehension(st, t, f)
		}
		if i := indexTop(t, 1, isWord("if")); i > 0 {
			if e := indexTop(t, i+1, isWord("else")); e > 0 {
				return a.branches(st, t[i+1:e], t[:i], t[e+1:], whole)
			}
		}
	} else if q := indexTop(t, 0, isOp("?")); q >= 0 {
		if q+1 < len(t) && t[q+1].op(":") {
			return or(a.expr(st, t[:q], whole), a.expr(st, t[q+2:], whole))
		}
		if c := ternaryColon(t, q); c > 0 {
			return a.branches(st, t[:q], t[q+1:c], t[c+1:], whole)
		}
	}

	// Logical operators: PHP's give a boolean; JavaScript's and Python's give an operand.
	logic := func(x Token) bool {
		return x.op("&&") || x.op("||") || x.word("and") || x.word("or") || a.php && x.word("xor")
	}
	if indexTop(t, 0, logic) >= 0 {
		if a.php {
			return val{}
		}
		return a.anyOf(st, splitTop(t, logic), whole)
	}
	if indexTop(t, 0, isOp("??")) >= 0 {
		return a.anyOf(st, splitTop(t, isOp("??")), whole)
	}
	if indexTop(t, 0, a.isCompare) >= 0 || t[0].op("!") || a.py && t[0].word("not") {
		return val{}
	}
	if a.php && indexTop(t, 0, isOp("=>")) >= 0 {
		return a.anyOf(st, splitTop(t, isOp("=>")), whole)
	}
	if a.py && indexTop(t, 0, isOp(":")) >= 0 {
		return a.anyOf(st, splitTop(t, isOp(":")), whole)
	}

	var v val
	terms := 0
	for i := 0; i < len(t); {
		tk := t[i]
		if tk.Kind == Op && !isOpen(tk) || tk.Kind == Ident && a.kw[tk.Text] || tk.Kind > Op {
			if tk.word("typeof") && a.js {
				_, e := a.term(st, t, i+1, false)
				i, terms = max(e, i+1), terms+1
				continue
			}
			i++
			continue
		}
		tv, e := a.term(st, t, i, whole)
		v.weak = weakOf(v.taint, v.weak, tv.taint, tv.weak)
		v.taint = v.taint || tv.taint
		v.emb = v.emb || tv.emb
		v.san = tv.san
		terms++
		i = max(e, i+1)
	}
	if terms != 1 {
		v.san = false
		v.emb = v.emb || v.taint // "SELECT " . $x, "a" + x, "%s" % x
	}
	return v
}

func or(x, y val) val {
	return val{taint: x.taint || y.taint, emb: x.emb || y.emb, weak: weakOf(x.taint, x.weak, y.taint, y.weak)}
}

func (a *analysis) anyOf(st state, parts [][]Token, whole bool) val {
	var v val
	for _, p := range parts {
		v = or(v, a.expr(st, p, whole))
	}
	return v
}

func (a *analysis) branches(st state, cond, yes, no []Token, whole bool) val {
	s1, _ := a.refine(st, cond, true)
	s2, _ := a.refine(st, cond, false)
	return or(a.expr(s1, yes, whole), a.expr(s2, no, whole))
}

// ternaryColon finds the ":" matching the "?" at q.
func ternaryColon(t []Token, q int) int {
	depth, nest := 0, 0
	for j := q + 1; j < len(t); j++ {
		switch {
		case isOpen(t[j]):
			depth++
		case isClose(t[j]):
			depth--
		case depth == 0 && t[j].op("?"):
			nest++
		case depth == 0 && t[j].op(":"):
			if nest == 0 {
				return j
			}
			nest--
		}
	}
	return -1
}

// comprehension evaluates a Python comprehension: for clauses bind their targets,
// if clauses act as checks on them.
func (a *analysis) comprehension(st state, t []Token, f int) val {
	x := st.clone()
	rest := t[f:]
	clause := func(t Token) bool { return t.word("for") || t.word("if") }
	for len(rest) > 0 {
		next := indexTop(rest, 1, clause)
		if next < 0 {
			next = len(rest)
		}
		switch {
		case rest[0].word("for"):
			in := indexTop(rest[:next], 1, isWord("in"))
			if in < 0 {
				return a.expr(x, t[:f], false)
			}
			v := a.expr(x, rest[in+1:next], false)
			for _, tg := range a.targetList(rest[1:in]) {
				a.setTarget(x, tg, v, "=", false)
			}
		case rest[0].word("if"):
			x, _ = a.refine(x, rest[1:next], true)
		default:
			return a.expr(x, t[:f], false)
		}
		rest = rest[next:]
	}
	return a.expr(x, t[:f], false)
}

// term evaluates one operand starting at i and returns where it ends.
func (a *analysis) term(st state, t []Token, i int, whole bool) (val, int) {
	if i >= len(t) {
		return val{}, i
	}
	if end, _, _, ok := a.sanitizerAt(st, t, i); ok {
		return a.postfix(st, t, i, end, val{san: true}, whole)
	}
	tk := t[i]
	switch {
	case tk.Kind == Str:
		return a.postfix(st, t, i, i+1, a.strVal(st, tk), whole)
	case tk.op("("):
		c := closeOf(t, i)
		inner := inside(t, i, c)
		if a.php && len(inner) == 1 && inner[0].Kind == Ident && phpCasts[strings.ToLower(inner[0].Text)] {
			if numericCasts[strings.ToLower(inner[0].Text)] {
				_, e := a.term(st, t, c+1, false)
				return val{}, e // (int) $x: a number carries no injection
			}
			return a.term(st, t, c+1, whole) // (string) $x, (array) $x: the value passes through
		}
		return a.postfix(st, t, i, c+1, a.expr(st, inner, whole), whole)
	case tk.op("[") || tk.op("{"):
		c := closeOf(t, i)
		return a.postfix(st, t, i, c+1, a.literal(st, inside(t, i, c), tk.Text, whole), whole)
	case tk.Kind == Ident && numericFuncs[a.lang()][tk.Text] && i+1 < len(t) && t[i+1].op("(") && (i == 0 || !memberOp(a.php, t[i-1])):
		return a.postfix(st, t, i, closeOf(t, i+1)+1, val{}, whole) // intval($x), int(x), Number(x)
	case tk.Kind == Var || tk.Kind == Ident:
		return a.postfix(st, t, i, i+1, val{}, whole)
	}
	return val{}, i + 1
}

// numericCasts and numericFuncs turn any value into a number (or a boolean), which
// carries no injection in any rule.
var numericCasts = map[string]bool{"int": true, "integer": true, "float": true, "double": true, "bool": true, "boolean": true}

var numericFuncs = map[string]map[string]bool{
	"php":    words("intval absint floatval boolval"),
	"python": words("int float bool len"),
	"js":     words("parseInt parseFloat Number Boolean"),
}

func (a *analysis) lang() string {
	switch {
	case a.php:
		return "php"
	case a.py:
		return "python"
	}
	return "js"
}

var phpCasts = map[string]bool{"int": true, "integer": true, "float": true, "double": true, "bool": true, "boolean": true,
	"string": true, "array": true, "object": true, "binary": true}

// postfix evaluates the accesses after a base (t[start:baseEnd]): member names,
// indexes and calls, applying sources, member sanitizers and the state.
func (a *analysis) postfix(st state, t []Token, start, baseEnd int, v val, whole bool) (val, int) {
	key := ""
	if baseEnd == start+1 && (t[start].Kind == Var || t[start].Kind == Ident) && !v.san {
		key = t[start].Text
	}
	srcEnd := -1
	source := func(pos int) {
		if a.noSrc {
			return
		}
		for _, s := range a.r.sources {
			if s.text == nil && s.at(t, pos, false) {
				if e := pos + len(s.toks); srcEnd < 0 || e < srcEnd {
					srcEnd = e
				}
			}
		}
	}
	apply := func(pos int) {
		if srcEnd >= 0 && pos >= srcEnd {
			v, srcEnd = val{taint: true}, -2
		}
		if key != "" {
			if e, ok := st[key]; ok {
				v = val{taint: e.taint || a.raw && e.raw, san: e.san, emb: e.emb, weak: e.weak}
			}
		}
	}
	if !v.san {
		source(start)
	}
	apply(baseEnd)
	j := baseEnd
	for j < len(t) && a.b.step() {
		if end, _, _, ok := a.memberSanitizerAt(t, j); ok {
			v, key, srcEnd = val{san: true}, "", -1
			j = end
			continue
		}
		source(j)
		tk := t[j]
		switch {
		case memberOp(a.php, tk) && j+1 < len(t) && (t[j+1].Kind == Ident || t[j+1].Kind == Var):
			// flask.request.form, self.request.GET: a source can start at a member.
			source(j + 1)
			if key != "" {
				key += sepCh + "." + t[j+1].Text
			}
			j += 2
		case tk.op("?.") && j+1 < len(t) && (t[j+1].op("(") || t[j+1].op("[")):
			j++
			continue
		case tk.op("["):
			c := closeOf(t, j)
			if key != "" {
				key += sepCh + "[" + idxKey(inside(t, j, c)) + "]"
			}
			j = c + 1
		case tk.op("("):
			c := closeOf(t, j)
			fn := ""
			if j == baseEnd && a.php && t[start].Kind == Ident {
				fn = t[start].Text
			}
			var sum *summary
			key := ""
			if j-1 == start || j-3 == start && j-2 > start && memberOp(a.php, t[j-2]) {
				key = a.calleeKey(t, j-1)
				sum = a.callSummary(t, j-1, key)
			}
			if sum != nil && !a.raw {
				v = a.callVal(st, sum, callArgs(t, j))
			} else if a.argsTaint(st, inside(t, j, c), fn) {
				// "...".format(x), sprintf("... %s", $x), implode(...): the input becomes part of a string
				name := t[j-1].Text
				v = val{taint: true, emb: t[start].Kind == Str || formatFuncs[name] || a.lib && a.argsEmb(st, inside(t, j, c)),
					// A function of this file left without a summary holds no sanitizer: what goes
					// through it is the input, not a guess.
					weak: !(t[start].Kind == Str || formatFuncs[name] || a.passes(t, start, j-1) || key != "" && !a.returnsUnknown(key))}
			}
			if key != "" {
				key += sepCh + "()"
			}
			j = c + 1
		default:
			if srcEnd >= 0 {
				v = val{taint: true}
			}
			return v, j
		}
		apply(j)
	}
	if srcEnd >= 0 {
		v = val{taint: true}
	}
	return v, j
}

// argsTaint reports whether a call's arguments carry taint into its result. Most
// calls pass on any argument's taint. In PHP, array_intersect and
// array_intersect_key return the values and keys of their first argument;
// WordPress's apply_filters($tag, $value, ...) returns the filtered $value.
func (a *analysis) argsTaint(st state, inner []Token, fn string) bool {
	args := splitTop(inner, isComma)
	switch fn {
	case "array_intersect", "array_intersect_key":
		args = args[:min(len(args), 1)]
	case "apply_filters":
		args = args[min(len(args), 1):min(len(args), 2)]
	}
	for _, arg := range args {
		if a.argVal(st, arg, false).taint {
			return true
		}
	}
	return false
}

// passFuncs return their input reshaped but whole (decoded, trimmed, case or
// slashes changed): input through them is still the input, not a guess, so a
// webshell's system(base64_decode($c)) is followed into other functions.
var passFuncs = map[string]map[string]bool{
	"php": words("trim ltrim rtrim base64_decode urldecode rawurldecode stripslashes stripcslashes strtolower strtoupper " +
		"ucfirst ucwords lcfirst str_replace str_ireplace substr strrev str_pad hex2bin html_entity_decode " +
		"htmlspecialchars_decode wp_unslash gzinflate gzuncompress gzdecode str_rot13 convert_uudecode strval"),
	"python": words("unquote unquote_plus b64decode urlsafe_b64decode decode str bytes"),
	"js":     words("decodeURIComponent decodeURI unescape atob String trim from"),
}

// passes reports whether the call named at t[n] (the chain starts at start) is
// one of passFuncs: a bare call, or one on a module known to hold them
// (base64.b64decode, urllib.parse.unquote, Buffer.from), not validator.trim().
func (a *analysis) passes(t []Token, start, n int) bool {
	if !passFuncs[a.lang()][t[n].Text] {
		return false
	}
	return n == start || n >= start+2 && memberOp(a.php, t[n-1]) && passModules[t[n-2].Text]
}

var passModules = words("base64 parse binascii codecs html Buffer")

// formatFuncs build a string from their arguments.
var formatFuncs = words("sprintf vsprintf implode join str_replace strtr format")

// argsEmb reports whether an argument carries embedded input.
func (a *analysis) argsEmb(st state, inner []Token) bool {
	for _, arg := range splitTop(inner, isComma) {
		if a.argVal(st, arg, false).emb {
			return true
		}
	}
	return false
}

// hits reports whether a value reaching a sink is reported: in library mode
// only input embedded in a larger string is (a parameter passed as is, such as
// a query string given to a query method, is what that API is for).
//
// Inside a summary run a value that went through a call the analysis does not
// know does not count either: the summary would carry the guess into callers.
func (a *analysis) hits(v val) bool {
	return v.taint && (!a.lib || v.emb) && (a.summ == nil || !v.weak)
}

// argVal evaluates one call argument, without a keyword (name=, name:) or spread.
func (a *analysis) argVal(st state, arg []Token, whole bool) val {
	if len(arg) > 1 && arg[0].Kind == Ident && (a.py && arg[1].op("=") || a.php && arg[1].op(":")) {
		arg = arg[2:]
	}
	for len(arg) > 0 && (arg[0].op("...") || arg[0].op("*") || arg[0].op("**")) {
		arg, whole = arg[1:], false
	}
	return a.expr(st, arg, whole)
}

func (a *analysis) strVal(st state, tk Token) val {
	if tk.Flags&FlagRegex != 0 {
		return val{}
	}
	for _, s := range a.r.textSources {
		if !a.noSrc && s.text.MatchString(tk.Text) {
			return val{taint: true}
		}
	}
	var v val
	for _, p := range tk.Parts {
		if pv := a.expr(st, p.Toks, false); pv.taint {
			v.weak = weakOf(v.taint, v.weak, true, pv.weak)
			v.taint, v.emb = true, true // "WHERE id = $id", f"...{x}", `...${x}`
		}
	}
	return v
}

// literal evaluates an array, object, dict, list or set literal.
func (a *analysis) literal(st state, inner []Token, open string, whole bool) val {
	if a.py && indexTop(inner, 0, isWord("for")) > 0 {
		return a.expr(st, inner, false)
	}
	var v val
	for _, e := range splitTop(inner, isComma) {
		if len(e) == 0 {
			continue
		}
		spread := e[0].op("...") || e[0].op("**") || e[0].op("*")
		if whole && !spread {
			continue
		}
		if spread {
			e = e[1:]
		}
		if a.js && open == "{" && len(e) > 1 {
			if (e[0].Kind == Ident || e[0].Kind == Str || e[0].Kind == Num) && e[1].op(":") {
				e = e[2:]
			} else if e[0].op("[") {
				if c := closeOf(e, 0); c+1 < len(e) && e[c+1].op(":") {
					v = or(v, a.expr(st, e[1:c], false))
					e = e[c+2:]
				}
			}
		}
		v = or(v, a.expr(st, e, false))
	}
	return v
}

// ---- sanitizers and checks ----

// sanitizerAt matches a sanitizer that starts at i (not a method) and returns
// where its effect ends: after its call, or after the operand of a cast or typeof.
func (a *analysis) sanitizerAt(st state, t []Token, i int) (end int, s *pat, open int, ok bool) {
	if a.raw {
		return 0, nil, -1, false
	}
	for _, s := range a.r.sanitizers {
		if s.member || !s.at(t, i, true) {
			continue
		}
		end, open := a.patEnd(t, i, s)
		if open < 0 && (s.toks[0].op("(") || len(s.toks) == 1 && s.toks[0].word("typeof")) && end < len(t) {
			_, end = a.term(st, t, end, false)
		}
		return end, s, open, true
	}
	return 0, nil, -1, false
}

// memberSanitizerAt matches a method sanitizer (".resolve(", "->prepare(") at i.
func (a *analysis) memberSanitizerAt(t []Token, i int) (end int, s *pat, open int, ok bool) {
	if a.raw {
		return 0, nil, -1, false
	}
	for _, s := range a.r.sanitizers {
		if s.member && s.at(t, i, false) {
			end, open := a.patEnd(t, i, s)
			return end, s, open, true
		}
	}
	return 0, nil, -1, false
}

// patEnd returns where a matched pattern's call ends and the index of its "(".
func (a *analysis) patEnd(t []Token, i int, s *pat) (end, open int) {
	end, open = i+len(s.toks), -1
	if k := s.callParen(); k >= 0 {
		open = i + k
	} else if end < len(t) && t[end].op("(") {
		open = end
	}
	if open >= 0 {
		end = closeOf(t, open) + 1
	}
	return end, open
}

type keyRef struct {
	key string
	src bool
}

// prefixChecks compare string prefixes; they protect a path only against a base
// that ends with a separator.
var prefixChecks = map[string]bool{"str_starts_with": true, "strncmp": true, "strncasecmp": true, "strpos": true,
	"stripos": true, "startsWith": true, "startswith": true}

// predicates are the sanitizers that answer yes or no about a value, so using
// them as a condition validates it. A transforming sanitizer (intval, basename,
// Number) cleans only its result: if (intval($x)) says nothing about $x.
var predicates = map[string]bool{"in_array": true, "array_key_exists": true, "is_relative_to": true,
	"ctype_digit": true, "ctype_alnum": true, "is_numeric": true, "is_int": true, "isInteger": true, "isSafeInteger": true,
	"str_starts_with": true, "strncmp": true, "strncasecmp": true, "strpos": true, "stripos": true,
	"startsWith": true, "startswith": true, "validate_file": true}

// zeroMeansMatch are comparisons for which "=== 0" means the check passed.
var zeroMeansMatch = map[string]bool{"strncmp": true, "strncasecmp": true, "strcmp": true, "strcasecmp": true,
	"strpos": true, "stripos": true, "validate_file": true}

// refine returns a copy of st for the path where cond is truth, with the values
// that a check in cond validates made clean, and the keys it cleaned.
func (a *analysis) refine(st state, cond []Token, truth bool) (state, []string) {
	out := st.clone()
	cond = stripParens(cond)
	split := func(t Token) bool { return t.op("||") || t.word("or") }
	if truth {
		split = func(t Token) bool { return t.op("&&") || t.word("and") }
	}
	var cleaned []string
	other := func(t Token) bool { return t.op("&&") || t.word("and") }
	if truth {
		other = func(t Token) bool { return t.op("||") || t.word("or") }
	}
	if parts := splitTop(cond, other); len(parts) > 1 && len(splitTop(cond, split)) == 1 {
		// !(A && B) is !A || !B, and A || B holds with A or with B: a value is
		// validated where every part on its own validates it.
		var common map[string]bool
		for _, p := range parts {
			_, ck := a.refine(st, p, truth)
			set := map[string]bool{}
			for _, k := range ck {
				if common == nil || common[k] {
					set[k] = true
				}
			}
			common = set
		}
		for k := range common {
			e := out[k]
			e.taint = false
			out[k] = e
			cleaned = append(cleaned, k)
		}
		slices.Sort(cleaned)
		return out, cleaned
	}
	for _, atom := range splitTop(cond, split) {
		pos, keys := a.guard(st, atom)
		if keys == nil || pos != truth {
			continue
		}
		for _, k := range keys {
			e := out[k.key]
			e.taint, e.src = false, e.src || k.src // keep what else is known (a base's separator)
			out[k.key] = e
			cleaned = append(cleaned, k.key)
		}
	}
	return out, cleaned
}

// guard reads one condition atom. When it is a check, keys are the values it
// validates and pos tells whether the atom is true when the check passes.
func (a *analysis) guard(st state, atom []Token) (pos bool, keys []keyRef) {
	pos = true
	atom = stripParens(atom)
	for len(atom) > 0 && (atom[0].op("!") || a.py && atom[0].word("not")) {
		pos, atom = !pos, stripParens(atom[1:])
	}
	if len(atom) == 0 {
		return pos, nil
	}
	// PHP empty($x) and isset($x): an empty or unset value carries no input.
	if n := len(atom); a.php && n > 3 && (atom[0].word("empty") || atom[0].word("isset")) && atom[1].op("(") && closeOf(atom, 1) == n-1 {
		arg := atom[2 : n-1]
		if _, _, ok := a.pathKey(arg); !ok {
			return pos, nil
		}
		if atom[0].word("isset") {
			pos = !pos // the check (the value is unset) holds when isset is false
		}
		return pos, a.keysOf(arg)
	}
	if a.py {
		if i := indexTop(atom, 0, isWord("in")); i > 0 {
			x := atom[:i]
			if atom[i-1].word("not") {
				pos, x = !pos, atom[:i-1]
			}
			if a.allowlist(st, atom[i+1:]) {
				return pos, a.keysOf(x)
			}
			return pos, nil
		}
	}
	if i := indexTop(atom, 0, a.isCompare); i > 0 {
		lhs, op, rhs := atom[:i], atom[i].Text, atom[i+1:]
		if isLiteral(lhs) {
			lhs, rhs = rhs, lhs
		}
		eq, ne := op == "==" || op == "===", op == "!=" || op == "!==" || op == "<>"
		if !eq && !ne || len(lhs) == 0 || len(rhs) != 1 {
			return pos, nil
		}
		// $order === 'ASC': where it holds, the value is that literal. Loose == is
		// trusted only against a plain string ("abc" == true holds in PHP).
		if _, _, ok := a.pathKey(lhs); ok && isLiteral(rhs) && (rhs[0].Kind == Str && len(rhs[0].Parts) == 0 || a.py || op == "===" || op == "!==") {
			if ne {
				pos = !pos
			}
			return pos, a.keysOf(lhs)
		}
		if a.js && lhs[0].word("typeof") {
			if !a.hasSanitizerWord("typeof") || rhs[0].Kind != Str {
				return pos, nil
			}
			if ne {
				pos = !pos
			}
			return pos, a.keysOf(lhs[1:])
		}
		switch strings.ToLower(rhs[0].Text) {
		case "true":
			if ne {
				pos = !pos
			}
		case "0":
			if zeroMeansMatch[lhs[0].Text] == ne {
				pos = !pos
			}
		case "false", "null", "none":
			if eq {
				pos = !pos
			}
		default:
			return pos, nil
		}
		atom = stripParens(lhs)
	} else if len(atom) > 0 && zeroIsValid[atom[0].Text] {
		pos = !pos // if (validate_file($f)) { wp_die(); }: a non-zero result means invalid
	}
	if keys, onMatch, ok := a.regexCheck(atom); ok {
		if !onMatch {
			pos = !pos // preg_match('/[^a-z0-9_]/', $x): a match means invalid
		}
		return pos, keys
	}
	return pos, a.checkKeys(st, atom)
}

// zeroIsValid are checks that return 0 for a valid value and an error code otherwise.
var zeroIsValid = map[string]bool{"validate_file": true}

func isLiteral(t []Token) bool {
	if len(t) != 1 {
		return false
	}
	switch t[0].Kind {
	case Num, Str:
		return true
	case Ident:
		switch strings.ToLower(t[0].Text) {
		case "true", "false", "null", "none", "undefined":
			return true
		}
	}
	return false
}

func (a *analysis) hasSanitizerWord(w string) bool {
	for _, s := range a.r.sanitizers {
		if len(s.toks) == 1 && s.toks[0].word(w) {
			return true
		}
	}
	return false
}

// checkKeys recognises a predicate call: an allowlist lookup, or one of the rule's
// sanitizers used as a check (in_array, str_starts_with, .startsWith, .is_relative_to).
func (a *analysis) checkKeys(st state, atom []Token) []keyRef {
	n := len(atom)
	if keys := a.validatorKeys(st, atom); keys != nil {
		return keys
	}
	// hash_equals(sign($v), $_POST['h']), hmac.compare_digest(...): an integrity
	// check. What it validates is the value fed into a keyed MAC or signature on
	// one side, never the other side as given (the attacker's), nor a value under
	// an unkeyed hash (md5($v): the attacker computes that too).
	if n > 2 && atom[n-1].op(")") && (a.php && atom[0].word("hash_equals") && atom[1].op("(") ||
		a.py && n > 4 && atom[0].word("hmac") && atom[1].op(".") && atom[2].word("compare_digest") && atom[3].op("(")) {
		open := 1
		if a.py {
			open = 3
		}
		if closeOf(atom, open) == n-1 {
			var keys []keyRef
			for _, arg := range splitTop(inside(atom, open, n-1), isComma) {
				keys = append(keys, a.macKeys(st, arg)...)
			}
			if len(keys) > 0 {
				return keys
			}
			return nil
		}
	}
	// PHP in_array($x, $allowed), array_key_exists($x, $map), and WordPress
	// validate_file($x, $allowed), which ends in the same in_array check.
	// The list decides: a rule listing in_array as a sanitizer gets no other way
	// round a list made of input.
	if a.php && n > 2 && (atom[0].word("in_array") || atom[0].word("array_key_exists") || atom[0].word("validate_file")) &&
		atom[1].op("(") && closeOf(atom, 1) == n-1 {
		args := splitTop(atom[2:n-1], isComma)
		if len(args) >= 2 && a.allowlist(st, args[1]) && !(atom[0].word("in_array") && looseNumbers(args)) {
			return a.keysOf(args[0])
		}
		return nil
	}
	// JavaScript ALLOWED.includes(x) and ALLOWED.has(x).
	if a.js && n > 4 && atom[n-1].op(")") {
		open := openOf(atom, n-1)
		if open >= 2 && atom[open-2].op(".") && (atom[open-1].word("includes") || atom[open-1].word("has")) &&
			a.allowlist(st, atom[:open-2]) {
			return a.keysOf(atom[open+1 : n-1])
		}
	}
	if end, s, open, ok := a.sanitizerAt(st, atom, 0); ok && end == n {
		var args [][]Token
		if open >= 0 {
			args = splitTop(inside(atom, open, end-1), isComma)
		}
		if !predicates[s.name] || prefixChecks[s.name] && !a.anySep(st, args) {
			return nil
		}
		if s.name == "validate_file" && (len(args) < 2 || !a.allowlist(st, args[1])) {
			return nil // without a list of allowed files it lets /etc/passwd through
		}
		return a.keysOf(atom)
	}
	depth := 0
	for m := 0; m < n; m++ {
		switch {
		case isOpen(atom[m]):
			depth++
		case isClose(atom[m]):
			depth--
		case depth == 0 && m > 0 && memberOp(a.php, atom[m]):
			end, s, open, ok := a.memberSanitizerAt(atom, m)
			if !ok || end != n {
				continue
			}
			var args [][]Token
			if open >= 0 {
				args = splitTop(inside(atom, open, end-1), isComma)
			}
			if !predicates[s.name] || prefixChecks[s.name] && !a.anySep(st, args) {
				return nil
			}
			return append(a.keysOf(atom[:m]), a.keysOf(inside(atom, open, end-1))...)
		}
	}
	return nil
}

// looseNumbers reports an in_array without strict comparison against a list
// holding numbers: before PHP 8, "1 OR 1=1" == 1 holds.
func looseNumbers(args [][]Token) bool {
	if len(args) >= 3 && len(args[2]) == 1 && args[2][0].word("true") {
		return false
	}
	for _, tk := range args[1] {
		if tk.Kind == Num {
			return true
		}
	}
	return false
}

// macKeys returns the values a keyed MAC or signature call validates: the
// arguments of hash_hmac(algo, $v, $key) with a key that is not input, of
// Python's hmac.new(key, v), or of a function of the code's own (a method that
// signs with a secret). Anything else validates nothing.
func (a *analysis) macKeys(st state, arg []Token) []keyRef {
	n := len(arg)
	if n < 3 || !arg[n-1].op(")") {
		return nil
	}
	open := openOf(arg, n-1)
	if open < 1 || arg[open-1].Kind != Ident {
		return nil
	}
	name := arg[open-1].Text
	args := splitTop(inside(arg, open, n-1), isComma)
	switch {
	case unkeyedHashes[strings.ToLower(name)]:
		return nil
	case a.php && strings.EqualFold(name, "hash_hmac"):
		if len(args) < 3 || a.fromRequest(st, args[2]) {
			return nil // no key, or a key the attacker chooses
		}
		return a.keysOf(args[1])
	case a.py && name == "new" && open >= 3 && arg[open-3].word("hmac"):
		if len(args) < 2 || a.fromRequest(st, args[0]) {
			return nil
		}
		return a.keysOf(args[1])
	case !a.php && !a.py:
		return nil
	}
	var keys []keyRef
	for _, x := range args {
		keys = append(keys, a.keysOf(x)...)
	}
	return keys
}

// validatorKeys returns what a call to a validator of the code's own checks
// (if (!is_valid_column($t, $c)) return;): the arguments its summary says a
// true result validates.
func (a *analysis) validatorKeys(st state, atom []Token) []keyRef {
	n := len(atom)
	if n < 3 || !atom[n-1].op(")") || a.sc == nil && a.proj == nil {
		return nil
	}
	open := openOf(atom, n-1)
	if open < 1 || open > 4 || !atom[open].op("(") {
		return nil
	}
	s := a.callSummary(atom, open-1, a.calleeKey(atom, open-1))
	if s == nil || s.checks|s.condChecks == 0 {
		return nil
	}
	args := callArgs(atom, open)
	idx := a.argIndex(s, args)
	var keys []keyRef
	for k, p := range idx {
		if p < 0 {
			continue
		}
		ok := s.checks&(1<<p) != 0
		if !ok && s.condChecks&(1<<p) != 0 {
			// ok($c, explode(',', $_GET['l'])): the list it checks against is input
			ok = true
			for j, arg := range args {
				if j != k && a.argVal(st, arg, false).taint {
					ok = false
				}
			}
		}
		if ok {
			keys = append(keys, a.keysOf(args[k])...)
		}
	}
	return keys
}

// fromRequest reports whether t carries input, or names request data at all
// (also while the rule's sources are off, in a summary run).
func (a *analysis) fromRequest(st state, t []Token) bool {
	if a.expr(st, t, false).taint {
		return true
	}
	for _, tk := range t {
		if (tk.Kind == Var || tk.Kind == Ident) && requestRoot(tk.Text) {
			return true
		}
	}
	return false
}

var unkeyedHashes = words("md5 sha1 crc32 hash md5_file sha1_file base64_encode hashlib sha256 sha512 md5sum strrev str_rot13 hexdigest digest")

func (a *analysis) anySep(st state, args [][]Token) bool {
	for _, arg := range args {
		if a.sepEnd(st, arg) {
			return true
		}
	}
	return false
}

// allowlist reports whether t can be a fixed set to look a value up in: not a
// string (that would be a substring test) and not user input.
func (a *analysis) allowlist(st state, t []Token) bool {
	t = stripParens(t)
	if len(t) == 0 || len(t) == 1 && t[0].Kind == Str {
		return false
	}
	if len(t) == 2 && t[0].op("[") && t[1].op("]") || len(t) == 3 && t[0].word("array") && t[1].op("(") && t[2].op(")") {
		return false // an empty list allows nothing, and validate_file_to_edit($f, []) checks nothing
	}
	// Only a list made with no input at all: a list an unknown function made
	// from input (array_map('trim', $_GET['l'])) may hold anything.
	return !a.expr(st, t, false).taint
}

// keysOf lists the plain paths in t (not function names, not method calls).
func (a *analysis) keysOf(t []Token) []keyRef {
	var out []keyRef
	for i := 0; i < len(t); {
		tk := t[i]
		if tk.Kind != Var && tk.Kind != Ident || a.kw[tk.Text] || i > 0 && memberOp(a.php, t[i-1]) {
			i++
			continue
		}
		j := i + 1
		for j < len(t) {
			if memberOp(a.php, t[j]) && j+1 < len(t) && (t[j+1].Kind == Ident || t[j+1].Kind == Var) && !(j+2 < len(t) && t[j+2].op("(")) {
				j += 2
			} else if t[j].op("[") {
				j = closeOf(t, j) + 1
			} else {
				break
			}
		}
		if j < len(t) && t[j].op("(") && j == i+1 {
			i = j // a function name
			continue
		}
		if key, _, ok := a.pathKey(t[i:j]); ok {
			src := false
			for k := i; k < j; k++ {
				for _, s := range a.r.sources {
					if s.text == nil && s.at(t[:j], k, false) {
						src = true
					}
				}
			}
			out = append(out, keyRef{key: key, src: src})
		}
		i = j
	}
	return out
}

// ---- sinks ----

func (a *analysis) sinks(st state, t []Token) {
	if !a.b.charge(len(t) * (len(a.r.sinks) + len(a.r.textSinks))) {
		return
	}
	for i := range t {
		for _, s := range a.r.sinks {
			if s.text == nil && s.at(t, i, true) {
				a.sink(st, t, i, s)
			}
		}
		if t[i].Kind == Str {
			for _, s := range a.r.textSinks {
				if loc := s.text.FindStringIndex(t[i].Text); loc != nil {
					a.textSink(st, t, i, loc[0])
				}
			}
		}
	}
	a.callSinks(st, t)
}

func (a *analysis) sink(st state, t []Token, i int, s *pat) {
	cond := a.r.args[s]
	end, open := a.patEnd(t, i, s)
	var region []Token
	switch {
	case open >= 0:
		region = t[open+1 : max(open+1, end-1)]
	case s.toks[len(s.toks)-1].Flags&FlagShell != 0:
		region = t[i:end]
	default:
		region = t[end:]
	}
	if cond != nil && (len(cond.when) > 0 && !a.when(cond.when, region) || a.unless(st, cond.unless, region)) {
		return
	}
	var recv []Token
	if s.member {
		if a.ownMethod(t, i+1) {
			return // $term_query->query($args): a method of the code's own, followed by its summary
		}
		recv = t[a.chainStart(t, i):i]
		if a.expr(st, recv, false).san {
			return // a method of an object a sanitizer made (SandboxedEnvironment().from_string)
		}
	}
	whole := cond != nil && cond.whole
	emb := false
	hit := func(v val) bool {
		ok := a.hits(v)
		emb = emb || ok && v.emb
		return ok
	}
	reaches := func(arg []Token) bool {
		return hit(a.argVal(st, arg, whole)) && !(cond != nil && cond.leading && a.fixedStart(st, arg))
	}
	tainted := false
	switch {
	case cond != nil && cond.arg != nil && *cond.arg == 0:
		tainted = hit(a.expr(st, recv, false))
	case open >= 0:
		args := splitTop(region, isComma)
		if cond != nil && (cond.arg != nil || cond.name != "") {
			if arg, ok := a.condArg(args, cond); ok {
				tainted = reaches(arg)
			} else if spread := a.spreadArg(args); spread != nil {
				tainted = reaches(spread) // ...$args may hold it
			}
			break
		}
		for _, arg := range args {
			if reaches(arg) {
				tainted = true
				break
			}
		}
	default:
		tainted = hit(a.expr(st, region, whole))
	}
	if tainted {
		a.reportSink(loc{a.file, t[i].Line}, emb)
	}
}

// ownMethod reports whether the method called at t[j] resolves to a function of
// the code's own. A sink named by its method alone (->query) is then that
// function, not a database driver's method: whatever reaches a real sink inside
// it is found through its summary. (Where following calls is cut short, the
// file's result keeps what was found without them.)
//
// An interface or abstract method has no body: the object is some other class,
// maybe the driver's, so the sink still applies.
func (a *analysis) ownMethod(t []Token, j int) bool {
	if j >= len(t) || t[j].Kind != Ident || a.b.hit {
		return false
	}
	if k := a.calleeKey(t, j); k != "" {
		return hasBody(a.sc.funcs[k])
	}
	if a.proj == nil {
		return false
	}
	c, ok := a.callee(t, j)
	if !ok {
		return false
	}
	f, k := a.proj.resolve(a, c)
	if f == "" {
		return false
	}
	x := a.proj.analysisFor(a, f)
	return x != nil && x.sc != nil && hasBody(x.sc.funcs[k])
}

// hasBody reports whether every definition found has code in it.
func hasBody(infos []*fnInfo) bool {
	for _, fi := range infos {
		if len(fi.f.body) == 0 {
			return false
		}
	}
	return len(infos) > 0
}

// condArg finds the argument an [[args]] condition names: by its name when it
// is passed by name (preg_replace_callback(callback: $f, ...)), otherwise by
// position among the arguments before the first named one.
func (a *analysis) condArg(args [][]Token, cond *argCond) ([]Token, bool) {
	positional := len(args)
	for i, arg := range args {
		if name, ok := a.argName(arg); ok {
			positional = min(positional, i)
			if cond.name != "" && name == cond.name {
				return arg, true
			}
		}
	}
	if cond.arg != nil && *cond.arg >= 1 && *cond.arg <= positional {
		return args[*cond.arg-1], true
	}
	return nil, false
}

// argName returns the name of an argument passed by name (PHP name: $x, Python name=x).
func (a *analysis) argName(arg []Token) (string, bool) {
	if len(arg) > 1 && arg[0].Kind == Ident && (a.php && arg[1].op(":") || a.py && arg[1].op("=")) {
		return arg[0].Text, true
	}
	return "", false
}

// spreadArg returns an argument that spreads a list into the call (...$a, *a, **kw).
func (a *analysis) spreadArg(args [][]Token) []Token {
	for _, arg := range args {
		if len(arg) > 0 && (arg[0].op("...") || arg[0].op("*") || arg[0].op("**")) {
			return arg
		}
	}
	return nil
}

// when reports whether one of the fragments is among a call's arguments. A
// fragment ending in ":" or "=" names an option (shell:, shell=): it counts with
// any value except a literal false, 0, null or None.
func (a *analysis) when(ps []*pat, region []Token) bool {
	for _, p := range ps {
		for i := range region {
			if !p.at(region, i, false) {
				continue
			}
			if v := optionValue(p, region, i); v == nil || !falsy(v) {
				return true
			}
		}
	}
	return false
}

// unless reports whether one of the fragments makes the call safe. An option
// fragment (root:) counts only when its value is not user input. A fragment that
// is a single string ("--") ends the options of a command, so it counts only
// when no user input comes before it in its list.
func (a *analysis) unless(st state, ps []*pat, region []Token) bool {
	for _, p := range ps {
		for i := range region {
			if !p.at(region, i, false) {
				continue
			}
			if k := optionWithValue(p); k >= 0 {
				if tokensEqual(valueAt(region, i+k+1), p.toks[k+1:]) {
					return true
				}
				continue
			}
			if v := optionValue(p, region, i); v != nil {
				if !a.expr(st, v, false).taint {
					return true
				}
				continue
			}
			if len(p.toks) == 1 && p.toks[0].Kind == Str {
				start := listStart(region, i)
				if a.argsTaint(st, region[start:i], "") {
					continue
				}
				return true
			}
		}
		// Any other fragment (yaml.SafeLoader) must be a whole argument.
		for _, arg := range splitTop(region, isComma) {
			if tokensEqual(arg, p.toks) {
				return true
			}
		}
	}
	return false
}

// optionWithValue returns the index of the ":", "=" or "=>" in a fragment that
// names an option and its value (Loader=yaml.SafeLoader), or -1.
func optionWithValue(p *pat) int {
	for k, t := range p.toks {
		if k > 0 && k < len(p.toks)-1 && t.Kind == Op && (t.Text == "=" || t.Text == ":" || t.Text == "=>") {
			return k
		}
	}
	return -1
}

// valueAt returns an option's value starting at start: up to the next "," or
// closing bracket at the same depth.
func valueAt(t []Token, start int) []Token {
	end := len(t)
	for j, depth := start, 0; j < len(t); j++ {
		if isOpen(t[j]) {
			depth++
		} else if isClose(t[j]) {
			if depth == 0 {
				end = j
				break
			}
			depth--
		} else if depth == 0 && t[j].op(",") {
			end = j
			break
		}
	}
	return t[min(start, end):end]
}

func tokensEqual(a, b []Token) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !tokEq(b[i], a[i]) {
			return false
		}
	}
	return true
}

// optionValue returns the value after an option fragment matched at i, or nil
// when p is not an option fragment.
func optionValue(p *pat, t []Token, i int) []Token {
	last := p.toks[len(p.toks)-1]
	if last.Kind != Op || last.Text != ":" && last.Text != "=" {
		return nil
	}
	return valueAt(t, i+len(p.toks))
}

func falsy(v []Token) bool {
	if len(v) != 1 {
		return false
	}
	switch strings.ToLower(v[0].Text) {
	case "false", "0", "null", "none", "undefined":
		return v[0].Kind != Str
	}
	return false
}

// listStart returns the index after the bracket that encloses position i (or 0).
func listStart(t []Token, i int) int {
	depth := 0
	for j := i - 1; j >= 0; j-- {
		if isClose(t[j]) {
			depth++
		} else if isOpen(t[j]) {
			if depth == 0 {
				return j + 1
			}
			depth--
		}
	}
	return 0
}

// textSink handles a sink that is text in a string ("ORDER BY"): what follows the
// text, in the string's interpolations or in the operands joined after it, must
// not be user input.
func (a *analysis) textSink(st state, t []Token, k, off int) {
	tk := t[k]
	tainted := false
	for _, p := range tk.Parts {
		if p.Off >= off && a.expr(st, p.Toks, false).taint {
			tainted = true
		}
	}
	if !tainted {
		end, depth := len(t), 0
		for j := k + 1; j < len(t) && end == len(t); j++ {
			switch {
			case isOpen(t[j]):
				depth++
			case isClose(t[j]):
				if depth == 0 {
					end = j
				}
				depth--
			case depth == 0 && (t[j].op(",") || t[j].op(";")):
				end = j
			}
		}
		tainted = a.expr(st, t[k+1:end], false).taint
	}
	if tainted {
		a.report(tk.Line + strings.Count(tk.Text[:off], "\n"))
	}
}
