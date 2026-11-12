package engine

import "slices"

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
func (a *analysis) reach(start relNode) bool {
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
	} else if v, ok := sc.rel[start.key]; ok {
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
		if v, ok := sc.rel[n.key]; ok {
			found = v == 1
			continue
		}
		if !x.build() {
			return true // the clock ran out reading it: not known, not kept (the scan is cut by it)
		}
		if sc.direct[n.key] {
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
			sc.rel[start.key] = 1
		}
		return true
	}
	for v := range visited {
		if sc, _ := scOf(v.file); sc != nil {
			sc.rel[v.key] = 2
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
	direct, cross := map[string]bool{}, map[string][]relNode{}
	keys := make([]string, 0, len(sc.funcs))
	for k := range sc.funcs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, fi := range sc.funcs[k] {
			x := *a
			x.b, x.cls, x.parent, x.fname = rb, fi.f.class, fi.f.parent, fi.f.name
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
	sc.direct, sc.cross = direct, cross
	return true
}
