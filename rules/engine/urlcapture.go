package engine

import "slices"

// A parsed URL a function literal written inside another reaches by name (a
// closure, a callback: () => { u.host = v }, [v].forEach(h => { u.host = h }))
// may be changed when that function runs, which the analysis does not follow:
// such a name holds no checked URL (setURLOf). The test is by name, over the
// whole file, and errs towards more findings: any use of the name from a
// function that does not itself bind it counts, a read as well as a write.

// fnRegions: the function literals of a file, as token ranges.
type fnRegions struct {
	inner  []int  // per token: the innermost function whose body or parameters hold it, or -1
	param  []bool // per token: inside a function's parameter list
	parent []int  // per function: the function its start is inside, or -1
	free   map[string]bool
}

// captured reports whether a function of the file uses name without binding
// it while an enclosing one (or the module) binds it, declares it global or
// nonlocal, or whether the name is this or self (a member of the object,
// which any method may change).
func (a *analysis) captured(name string) bool {
	if name == "this" || name == "self" {
		return true
	}
	if a.fregs == nil {
		a.fregs = fileRegions(a.ftoks, a.py)
	}
	r := a.fregs
	if v, ok := r.free[name]; ok {
		return v
	}
	t := a.ftoks
	binds := map[int]bool{} // functions (-1: the module) where name is a local
	forced := map[int]bool{}
	var uses []int
	for j, tk := range t {
		if tk.Kind != Ident || tk.Text != name || j > 0 && (memberOp(false, t[j-1]) || t[j-1].op("?.")) {
			continue
		}
		in := r.inner[j]
		switch {
		case r.param[j]:
			binds[in] = true
		case inDeclare(t, j):
			forced[in] = true
		case !a.py && j > 0 && (t[j-1].word("const") || t[j-1].word("let") || t[j-1].word("var")):
			binds[in] = true
		case a.py && lineStart(t, j) && j+1 < len(t) && (t[j+1].op("=") || t[j+1].op(":")):
			binds[in] = true
		default:
			uses = append(uses, j)
		}
	}
	// a function that declares the name global or nonlocal rebinds the outer
	// u when it assigns it (Python's only way to change a parsed URL elsewhere)
	free := len(forced) > 0
	for _, j := range uses {
		f := r.inner[j]
		b := f
		for b >= 0 && !(binds[b] && !forced[b]) {
			b = r.parent[b]
		}
		if b != f {
			free = true
			break
		}
	}
	r.free[name] = free
	return free
}

// fileRegions finds the function literals of a file: JavaScript's function
// (...) {...}, (...) => {...} or an expression, a method's name(...) {...};
// Python's def and lambda.
func fileRegions(t []Token, py bool) *fnRegions {
	n := len(t)
	match := make([]int, n)
	var stack []int
	for i := range t {
		match[i] = -1
		switch {
		case isOpen(t[i]):
			stack = append(stack, i)
		case isClose(t[i]) && len(stack) > 0:
			o := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			match[o], match[i] = i, o
		}
	}
	type fnr struct{ start, ps, pe, bs, be int }
	var fs []fnr
	body := func(open int) (int, int, bool) {
		if open < n && t[open].op("{") && match[open] > open {
			return open + 1, match[open], true
		}
		return 0, 0, false
	}
	for i := 0; i < n; i++ {
		tk := t[i]
		switch {
		case !py && tk.word("function"):
			o := i + 1
			for o < n && !t[o].op("(") && o < i+4 {
				o++
			}
			if o < n && t[o].op("(") && match[o] > o {
				if bs, be, ok := body(match[o] + 1); ok {
					fs = append(fs, fnr{i, o + 1, match[o], bs, be})
				}
			}
		case !py && tk.op("=>"):
			ps, pe := i-1, i
			if i > 0 && t[i-1].op(")") && match[i-1] >= 0 {
				ps, pe = match[i-1]+1, i-1
			}
			if ps < 0 {
				ps = 0
			}
			if bs, be, ok := body(i + 1); ok {
				fs = append(fs, fnr{ps, ps, pe, bs, be})
			} else {
				fs = append(fs, fnr{ps, ps, pe, i + 1, i + 1 + len(stmtRest(t, i+1))})
			}
		case !py && tk.op(")") && i+1 < n && t[i+1].op("{") && match[i] > 0:
			o := match[i]
			if p := t[o-1]; p.Kind == Ident && !p.word("if") && !p.word("for") && !p.word("while") && !p.word("switch") &&
				!p.word("catch") && !p.word("with") && !p.word("function") && (o < 2 || !t[o-2].word("function")) {
				if bs, be, ok := body(i + 1); ok {
					fs = append(fs, fnr{o - 1, o + 1, i, bs, be}) // a method: name(...) {...}
				}
			}
		case py && tk.word("def"):
			o := i + 1
			for o < n && !t[o].op("(") && o < i+3 {
				o++
			}
			if o >= n || !t[o].op("(") || match[o] < 0 {
				continue
			}
			c := match[o] + 1
			for c < n && !t[c].op(":") {
				c++
			}
			fs = append(fs, fnr{i, o + 1, match[o], c + 1, pyBlockEnd(t, c+1)})
		case py && tk.word("lambda"):
			c, depth := i+1, 0
			for ; c < n; c++ {
				if isOpen(t[c]) {
					depth++
				} else if isClose(t[c]) {
					depth--
				} else if depth == 0 && t[c].op(":") {
					break
				}
			}
			if c < n {
				fs = append(fs, fnr{i, i + 1, c, c + 1, c + 1 + len(stmtRest(t, c+1))})
			}
		}
	}
	slices.SortStableFunc(fs, func(x, y fnr) int { return x.start - y.start })
	r := &fnRegions{inner: make([]int, n), param: make([]bool, n), parent: make([]int, len(fs)), free: map[string]bool{}}
	for i := range r.inner {
		r.inner[i] = -1
	}
	// fs is in the order the functions start, so an enclosing function is
	// filled in before the ones inside it, which then take their own tokens
	for k, f := range fs {
		r.parent[k] = r.inner[f.start]
		for j := f.ps; j < f.pe && j < n; j++ {
			r.inner[j], r.param[j] = k, true
		}
		for j := f.bs; j < f.be && j < n; j++ {
			r.inner[j], r.param[j] = k, false
		}
	}
	return r
}

// pyBlockEnd returns where the Python block starting at i ends: the Dedent
// closing its Indent, or the end of the line for a body on the def's line.
func pyBlockEnd(t []Token, i int) int {
	j := i
	for j < len(t) && t[j].Kind == Newline {
		j++
	}
	if j >= len(t) || t[j].Kind != Indent {
		for j < len(t) && t[j].Kind != Newline && t[j].Line == t[i-1].Line {
			j++
		}
		return j
	}
	depth := 0
	for ; j < len(t); j++ {
		switch t[j].Kind {
		case Indent:
			depth++
		case Dedent:
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return len(t)
}

// inDeclare reports whether t[j] is one of the names of a global or nonlocal
// statement: global u, nonlocal a, u.
func inDeclare(t []Token, j int) bool {
	for k := j - 1; k >= 0 && t[k].Line == t[j].Line; k -= 2 {
		if t[k].word("global") || t[k].word("nonlocal") {
			return true
		}
		if !t[k].op(",") || k == 0 || t[k-1].Kind != Ident {
			return false
		}
	}
	return false
}
