package engine

import (
	"slices"
	"strings"
)

// Relevance: whether a function matters to a rule, so that its summary is
// worth working out. A function matters when something in it does (a source,
// a sink, a sanitizer, a check: toksRelevant) or when a function it calls,
// in its file or another, matters. That is reachability in the call graph,
// which no order of asking changes: each file's functions are read once per
// rule for what they do themselves and whom they call (build), then a
// question walks the graph from the function asked about. Whatever a walk
// finds is kept: yes for the function asked about, no for every function a
// walk that found nothing went through (nothing they reach matters).

type relNode struct{ file, key string }

// reach walks the call graph from start.
func (a *analysis) reach(start relNode) bool { return a.walk(start, false) }

// reachSource walks it for what may bring the rule's input into a function's
// result on its own: a source of the rule, or a call the graph does not
// resolve (mayBringInput), in the function or a function it reaches.
func (a *analysis) reachSource(start relNode) bool { return a.walk(start, true) }

func (a *analysis) walk(start relNode, src bool) bool {
	memo := func(sc *summaries) map[string]uint8 {
		if src {
			return sc.srcRel
		}
		return sc.rel
	}
	direct := func(sc *summaries) map[string]bool {
		if src {
			return sc.srcMay
		}
		return sc.direct
	}
	scOf := func(f string) (*summaries, *analysis) {
		if f == a.file {
			return a.sc, a
		}
		if a.proj == nil {
			return nil, nil
		}
		x := a.proj.analysisFor(a, f)
		if x == nil {
			return nil, nil
		}
		return x.sc, x
	}
	if sc, _ := scOf(start.file); sc == nil {
		return false
	} else if v, ok := memo(sc)[start.key]; ok {
		return v == 1
	}
	visited := map[relNode]bool{}
	stack := []relNode{start}
	found := false
	for len(stack) > 0 && !found {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[n] {
			continue
		}
		visited[n] = true
		sc, x := scOf(n.file)
		if sc == nil {
			continue
		}
		if v, ok := memo(sc)[n.key]; ok {
			found = v == 1
			continue
		}
		if !x.build() {
			return true // the clock ran out reading it: not known, not kept (the scan is cut by it)
		}
		if direct(sc)[n.key] {
			found = true
			break
		}
		for _, k := range sc.ff.edges[n.key] {
			stack = append(stack, relNode{n.file, k})
		}
		for _, k := range sc.ff.unions[n.key] { // a $this union: its members
			stack = append(stack, relNode{n.file, k})
		}
		stack = append(stack, sc.cross[n.key]...)
	}
	if found {
		if sc, _ := scOf(start.file); sc != nil {
			memo(sc)[start.key] = 1
		}
		return true
	}
	for v := range visited {
		if sc, _ := scOf(v.file); sc != nil {
			memo(sc)[v.key] = 2
		}
	}
	return false
}

// build reads the file's functions once for this rule: what matters in each
// itself, and which functions of other files each calls (resolved from where
// it is written: its class, its file). Charged to nobody, bounded by the
// clock; false when the clock ran out.
func (a *analysis) build() bool {
	sc := a.sc
	if sc.direct != nil {
		return true
	}
	if !a.graph() {
		return false
	}
	rb := &budget{maxTok: 1 << 40, deadline: a.b.deadline}
	direct, srcMay, cross := map[string]bool{}, map[string]bool{}, map[string][]relNode{}
	keys := make([]string, 0, len(sc.funcs))
	for k := range sc.funcs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, fi := range sc.funcs[k] {
			x := *a
			x.b, x.cls, x.parent, x.fname = rb, fi.f.class, fi.f.parent, fi.f.name
			if !walkAll(fi.f.body, 0, func(t []Token) {
				if !srcMay[k] && x.mayBringInput(t) {
					srcMay[k] = true
				}
			}) {
				srcMay[k] = true // code nested too deep to read: it may
			}
			walkToks(fi.f.body, 0, func(t []Token) {
				if !direct[k] && x.toksRelevant(t) {
					direct[k] = true
				}
				if a.proj == nil {
					return
				}
				for i := 0; i+1 < len(t); i++ {
					if t[i].Kind != Ident || !t[i+1].op("(") || x.calleeKey(t, i) != "" {
						continue
					}
					if c, ok := x.callee(t, i); ok {
						if f, name, _, _ := a.proj.target(&x, c); f != "" {
							cross[k] = append(cross[k], relNode{f, name})
						}
					}
				}
			})
		}
	}
	if rb.timeHit {
		if a.proj != nil {
			a.proj.stop("following calls across files ran out of time")
			a.proj.byMachine = true
		}
		a.b.hit, a.b.timeHit = true, true
		return false
	}
	sc.direct, sc.srcMay, sc.cross = direct, srcMay, cross
	return true
}

// walkAll is walkToks that says whether it read everything: false when some
// code is nested deeper than it goes.
func walkAll(ss []*stmt, depth int, f func([]Token)) bool {
	if depth > maxNest {
		return len(ss) == 0
	}
	ok := true
	for _, s := range ss {
		f(s.toks)
		for _, fn := range s.funcs {
			ok = walkAll(fn.body, depth+1, f) && ok
		}
		if s.fn != nil && s.fn.name == "" {
			ok = walkAll(s.fn.body, depth+1, f) && ok
		}
		ok = walkAll(s.body, depth+1, f) && ok
		ok = walkAll(s.els, depth+1, f) && ok
		ok = walkAll(s.orelse, depth+1, f) && ok
		for _, h := range s.handlers {
			ok = walkAll(h, depth+1, f) && ok
		}
		for _, c := range s.cases {
			ok = walkAll(c, depth+1, f) && ok
		}
	}
	return ok
}

// mayBringInput reports whether t may bring the rule's input in by itself: one
// of its sources, or a call whose target the call graph does not know, which
// the analysis may still resolve to a function of the project (by an object's
// type, a callable string, a closure in a variable, an included file): a
// method of a name the project declares, a dynamic call ($f(), f()(), x[k]()),
// include or require, new of a class the project declares, or a string naming
// a function or method of the project. A call of a function the project does
// not declare (strlen, a library's) carries at most its arguments, so it is
// not counted.
func (a *analysis) mayBringInput(t []Token) bool {
	if !a.b.charge(len(t)) {
		return true
	}
	lang := a.lang()
	norm := func(n string) string {
		if lang == "php" {
			return strings.ToLower(n)
		}
		return n
	}
	declared := func(n string) bool {
		n = norm(n)
		if a.proj != nil && len(a.proj.declared[lang][n]) > 0 {
			return true
		}
		_, ok := a.sc.funcs[n]
		return ok || a.sc.ff.hasTail(n)
	}
	class := func(n string) bool {
		return a.proj != nil && len(a.proj.classes[lang][n]) > 0 || a.sc.ff.hasClass(n) || a.sc.ff.hasClass(norm(n))
	}
	for i := range t {
		for _, p := range a.r.sources {
			if p.text == nil && p.at(t, i, false) {
				return true
			}
		}
		tk := t[i]
		switch {
		case tk.Kind == Str:
			for _, p := range a.r.textSources {
				if p.text.MatchString(tk.Text) {
					return true
				}
			}
			if len(tk.Parts) > 0 || tk.Text != "" && declared(tk.Text) {
				return true // a callable string, or one with code inside
			}
		case lang == "php" && tk.Kind == Ident && (tk.Text == "include" || tk.Text == "include_once" || tk.Text == "require" || tk.Text == "require_once"):
			return true
		case tk.Kind == Ident && tk.Text == "new" && i+1 < len(t):
			if t[i+1].Kind != Ident || class(t[i+1].Text) {
				return true // new $cls, new Mailer: its constructor
			}
		}
		if i+1 >= len(t) || !t[i+1].op("(") {
			continue
		}
		switch {
		case tk.Kind == Var:
			return true // $f(): a closure or a callable in a variable
		case tk.op(")") || tk.op("]"):
			return true // f()(), $x[$k](), getattr(o, n)()
		case tk.Kind == Ident && !a.kw[tk.Text]:
			if a.calleeKey(t, i) != "" {
				continue // a function of the file: an edge of the graph
			}
			member := i > 0 && (memberOp(a.php, t[i-1]) || t[i-1].op("::"))
			if !member && a.proj != nil {
				if c, ok := a.callee(t, i); ok {
					if f, _, _, _ := a.proj.target(a, c); f != "" {
						continue // resolved across files: an edge of the graph
					}
				}
			}
			if declared(tk.Text) || a.proj != nil && a.proj.importedRelative(a.file, t, i) {
				return true // may be resolved during the analysis
			}
		}
	}
	return false
}
