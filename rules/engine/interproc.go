package engine

import (
	"slices"
	"strings"
)

// Calls inside one file are followed through function summaries. A summary
// tells, for one rule, what a named function does with its parameters: which
// of them reach a sink (and at which lines), which of them the return value
// carries, and whether the return value carries input of its own. A call to a
// function of the same file then uses the summary instead of the default (the
// result carries any argument's input, and no sink is reached).
//
// A call resolves to a summary when it names a function, a method through
// $this->, self::, static::, parent::, this. or Python's self./cls., or a
// variable a closure was assigned to ($cb = function ...; $cb($x)). Functions
// and methods share one name space per file; same-named ones are merged.
//
// Summaries are computed when a call first needs them, for the parameters in
// isolation: once with no parameter tainted, once with all of them, and, only
// when that differs, once per parameter. Recursion is resolved by recomputing
// the summary at the head of the cycle until it no longer changes. Depth, the
// number of runs per rule and file, and the rounds are capped; a file that hits
// a cap is reported with ErrLimit, as for any other limit.

const (
	maxSumParams = 16   // parameters a summary tracks
	maxSumDepth  = 32   // summaries being computed inside one another
	maxSumRuns   = 4000 // analyses of function bodies per rule and file
	maxSumRounds = 4    // recomputations at the head of a recursive cycle
)

// fnInfo is a named function of the file.
type fnInfo struct {
	f       *fn
	params  []string // parameter names in order ("" where there is no plain name)
	numeric []bool   // declared int, float or bool
	self    bool     // a Python method whose first parameter (self, cls) is the receiver
}

type summary struct {
	sink    [maxSumParams][]int // per parameter: the sink lines it reaches
	ret     uint32              // parameters whose input the return value carries
	retSrc  bool                // the return value carries input of its own
	retEmb  bool                // the returned input is embedded in a larger string
	retWeak bool                // the returned parameters' input went through calls the analysis does not know
}

func (s *summary) equal(o *summary) bool {
	if s.ret != o.ret || s.retSrc != o.retSrc || s.retEmb != o.retEmb || s.retWeak != o.retWeak {
		return false
	}
	for i := range s.sink {
		if !slices.Equal(s.sink[i], o.sink[i]) {
			return false
		}
	}
	return true
}

func (s *summary) reachesSink() bool {
	for _, l := range s.sink {
		if len(l) > 0 {
			return true
		}
	}
	return false
}

// summaries holds one rule's summaries for one file.
type summaries struct {
	funcs map[string][]*fnInfo
	done  map[string]*summary
	busy  map[string]bool
	again map[string]bool  // a call reached the name while its summary was being computed
	rel   map[string]uint8 // relevance to the rule: 0 not known yet, 1 yes, 2 no, 3 being worked out
	runs  int
	depth int
}

func newSummaries(funcs map[string][]*fnInfo) *summaries {
	if len(funcs) == 0 {
		return nil
	}
	return &summaries{funcs: funcs, done: map[string]*summary{}, busy: map[string]bool{}, again: map[string]bool{}, rel: map[string]uint8{}}
}

// summRun collects what one analysis of a function body found.
type summRun struct {
	lines map[int]bool
	ret   val
}

// collectFuncs finds the named functions of a file, and closures assigned to a
// plain name.
func collectFuncs(ss []*stmt, lang string) map[string][]*fnInfo {
	out := map[string][]*fnInfo{}
	var walk func(ss []*stmt, depth int)
	add := func(name string, f *fn) {
		if name != "" && f != nil {
			out[name] = append(out[name], paramInfo(f, lang))
		}
	}
	walk = func(ss []*stmt, depth int) {
		if depth > maxNest {
			return
		}
		for _, s := range ss {
			if s.fn != nil {
				add(s.fn.name, s.fn)
				walk(s.fn.body, depth+1)
			}
			if s.kind == sSimple && len(s.funcs) > 0 {
				t := s.toks
				for len(t) > 0 && t[0].Kind == Ident && declWords[t[0].Text] {
					t = t[1:]
				}
				if len(t) == 3 && (t[0].Kind == Ident || t[0].Kind == Var) && t[1].op("=") && t[2].Kind == Func && t[2].Fn < len(s.funcs) {
					add(t[0].Text, s.funcs[t[2].Fn])
				}
			}
			for _, f := range s.funcs {
				walk(f.body, depth+1)
			}
			walk(s.body, depth+1)
			walk(s.els, depth+1)
			walk(s.orelse, depth+1)
			for _, h := range s.handlers {
				walk(h, depth+1)
			}
			for _, c := range s.cases {
				walk(c, depth+1)
			}
		}
	}
	walk(ss, 0)
	return out
}

// paramInfo reads parameter names and numeric type declarations.
func paramInfo(f *fn, lang string) *fnInfo {
	fi := &fnInfo{f: f}
	for _, part := range splitTop(f.params, isComma) {
		name, numeric := "", false
		switch lang {
		case "php":
			for _, tk := range part {
				if tk.Kind == Var {
					name = tk.Text
					break
				}
				if tk.Kind == Ident && numericCasts[strings.ToLower(tk.Text)] {
					numeric = true
				}
			}
		case "python":
			p := part
			for len(p) > 0 && (p[0].op("*") || p[0].op("**")) {
				p = p[1:]
			}
			if len(p) > 0 && p[0].Kind == Ident {
				name = p[0].Text
			}
			if c := indexTop(p, 0, isOp(":")); c > 0 && c+1 < len(p) && p[c+1].Kind == Ident {
				numeric = numericCasts[p[c+1].Text] || p[c+1].Text == "int" || p[c+1].Text == "float"
			}
		case "js":
			if len(part) > 0 && part[0].Kind == Ident {
				name = part[0].Text
			}
		}
		fi.params = append(fi.params, name)
		fi.numeric = append(fi.numeric, numeric)
	}
	if lang == "python" && f.method && len(fi.params) > 0 && (fi.params[0] == "self" || fi.params[0] == "cls") {
		fi.params, fi.numeric, fi.self = fi.params[1:], fi.numeric[1:], true
	}
	return fi
}

// receivers are the objects through which a call reaches a method of the same class.
var receivers = map[string]bool{"$this": true, "self": true, "static": true, "parent": true, "this": true, "cls": true}

// calleeName returns the name a call resolves through, when t[i] is the name
// of a call (t[i+1] is "(") that may reach a function of this file.
func (a *analysis) calleeName(t []Token, i int) string {
	if a.sc == nil || i+1 >= len(t) || !t[i+1].op("(") || t[i].Kind != Ident && !(a.php && t[i].Kind == Var) {
		return ""
	}
	if i > 0 && (memberOp(a.php, t[i-1]) || a.php && t[i-1].op("\\")) {
		if t[i].Kind != Ident || i < 2 || !receivers[t[i-2].Text] || i > 2 && (memberOp(a.php, t[i-3]) || t[i-3].op("\\")) {
			return ""
		}
		return t[i].Text
	}
	if i > 0 && (t[i-1].word("function") || t[i-1].word("def") || t[i-1].word("new") || t[i-1].word("fn")) {
		return ""
	}
	return t[i].Text
}

// summaryOf returns the summary of a function of this file, computing it first
// if needed; nil when the name is not one, or while it is being computed.
func (a *analysis) summaryOf(name string) *summary {
	sc := a.sc
	if sc == nil || name == "" {
		return nil
	}
	if s, ok := sc.done[name]; ok {
		return s
	}
	infos := sc.funcs[name]
	if len(infos) == 0 || !a.relevant(name) {
		return nil
	}
	if sc.busy[name] {
		sc.again[name] = true
		return nil
	}
	if sc.depth >= maxSumDepth || sc.runs >= maxSumRuns || a.b.hit {
		a.b.tooDeep()
		return nil
	}
	sc.busy[name] = true
	sc.depth++
	var s *summary
	for round := 0; ; round++ {
		delete(sc.again, name)
		n := &summary{}
		for _, fi := range infos {
			a.summarize(fi, n)
		}
		stable := s != nil && n.equal(s)
		s = n
		if stable || !sc.again[name] {
			break
		}
		if round+1 >= maxSumRounds {
			a.b.tooDeep() // a recursive cycle that does not settle
			break
		}
		sc.done[name] = s // the next round sees this one
	}
	sc.done[name] = s
	delete(sc.busy, name)
	sc.depth--
	return s
}

// relevant reports whether a function can matter to the rule: its body holds
// one of the rule's sources, sinks or sanitizers (or a number conversion), or
// calls a function of the file that does.
// The others keep the default (the result carries any argument's input), which
// spares analysing every function of a large file for every rule.
func (a *analysis) relevant(name string) bool {
	sc := a.sc
	switch sc.rel[name] {
	case 1:
		return true
	case 2, 3:
		return false
	}
	sc.rel[name] = 3
	ok := false
	for _, fi := range sc.funcs[name] {
		if a.bodyRelevant(fi.f.body, 0) {
			ok = true
			break
		}
	}
	sc.rel[name] = 2
	if ok {
		sc.rel[name] = 1
	}
	return ok
}

func (a *analysis) bodyRelevant(ss []*stmt, depth int) bool {
	if depth > maxNest {
		return true
	}
	for _, s := range ss {
		if a.toksRelevant(s.toks) {
			return true
		}
		for _, f := range s.funcs {
			if a.bodyRelevant(f.body, depth+1) {
				return true
			}
		}
		if s.fn != nil && s.fn.name == "" && a.bodyRelevant(s.fn.body, depth+1) {
			return true
		}
		if a.bodyRelevant(s.body, depth+1) || a.bodyRelevant(s.els, depth+1) || a.bodyRelevant(s.orelse, depth+1) {
			return true
		}
		for _, h := range s.handlers {
			if a.bodyRelevant(h, depth+1) {
				return true
			}
		}
		for _, c := range s.cases {
			if a.bodyRelevant(c, depth+1) {
				return true
			}
		}
	}
	return false
}

func (a *analysis) toksRelevant(t []Token) bool {
	if !a.b.charge(len(t)) {
		return true
	}
	for i := range t {
		if t[i].Kind == Ident && i+1 < len(t) && t[i+1].op("(") && numericFuncs[a.lang()][t[i].Text] ||
			a.php && t[i].op("(") && i+2 < len(t) && t[i+2].op(")") && numericCasts[strings.ToLower(t[i+1].Text)] {
			return true // a helper that returns a number: its summary makes the result clean
		}
		for _, ps := range [][]*pat{a.r.sinks, a.r.sources, a.r.sanitizers} {
			for _, p := range ps {
				if p.text == nil && p.at(t, i, false) {
					return true
				}
			}
		}
		if t[i].Kind == Str {
			for _, ps := range [][]*pat{a.r.textSinks, a.r.textSources} {
				for _, p := range ps {
					if p.text.MatchString(t[i].Text) {
						return true
					}
				}
			}
		}
		if name := a.calleeName(t, i); name != "" && len(a.sc.funcs[name]) > 0 && a.relevant(name) {
			return true
		}
	}
	return false
}

// summarize adds what fi does to s.
func (a *analysis) summarize(fi *fnInfo, s *summary) {
	n := min(len(fi.params), maxSumParams)
	run := func(mask uint32) (map[int]bool, val) {
		x := &analysis{r: a.r, php: a.php, py: a.py, js: a.js, b: a.b, kw: a.kw, seen: map[int]bool{}, sc: a.sc,
			summ: &summRun{lines: map[int]bool{}}}
		st := state{}
		for i := 0; i < n; i++ {
			if p := fi.params[i]; p != "" && mask&(1<<i) != 0 {
				st[p] = entry{taint: true}
			}
		}
		a.sc.runs++
		x.block(fi.f.body, st)
		return x.summ.lines, x.summ.ret
	}
	base, baseRet := run(0)
	if baseRet.taint && !baseRet.weak {
		// Only input returned as is counts: a source passed through a call the
		// analysis does not know (sanitize_locale_name($_GET['l'])) is left out,
		// as it was before calls were followed.
		s.retSrc = true
		s.retEmb = s.retEmb || baseRet.emb
	}
	if n == 0 || a.b.hit {
		return
	}
	all, allRet := run(1<<n - 1)
	if !extra(all, base) && allRet.taint == baseRet.taint {
		return
	}
	for i := 0; i < n && !a.b.hit; i++ {
		if fi.params[i] == "" {
			continue
		}
		lines, ret := run(1 << i)
		for l := range lines {
			if !base[l] && !slices.Contains(s.sink[i], l) {
				s.sink[i] = append(s.sink[i], l)
			}
		}
		slices.Sort(s.sink[i])
		if ret.taint && !baseRet.taint {
			s.ret |= 1 << i
			s.retEmb = s.retEmb || ret.emb
			s.retWeak = s.retWeak || ret.weak
		}
	}
}

func extra(x, base map[int]bool) bool {
	for l := range x {
		if !base[l] {
			return true
		}
	}
	return false
}

// callArgs returns the arguments of the call whose "(" is at open.
func callArgs(t []Token, open int) [][]Token {
	c := closeOf(t, open)
	if c <= open {
		return nil
	}
	return splitTop(inside(t, open, c), isComma)
}

// callVal is the value of a call to a summarised function.
func (a *analysis) callVal(st state, s *summary, args [][]Token) val {
	v := val{taint: s.retSrc, emb: s.retEmb}
	for i, arg := range args {
		if i >= maxSumParams {
			break
		}
		if s.ret&(1<<i) != 0 {
			if av := a.argVal(st, arg, false); av.taint {
				v.weak = weakOf(v.taint, v.weak, true, av.weak || s.retWeak)
				v.taint, v.emb = true, v.emb || av.emb || s.retEmb
			}
		}
	}
	return v
}

// callSinks reports the sinks a call reaches through the callee's parameters.
func (a *analysis) callSinks(st state, t []Token) {
	if a.sc == nil {
		return
	}
	for i := 0; i+1 < len(t); i++ {
		name := a.calleeName(t, i)
		if name == "" {
			continue
		}
		s := a.summaryOf(name)
		if s == nil || !s.reachesSink() {
			continue
		}
		for k, arg := range callArgs(t, i+1) {
			if k >= maxSumParams || len(s.sink[k]) == 0 {
				continue
			}
			// Only input that did not come through an unknown call crosses into
			// another function's sinks: get_post($_GET['id']) is not the input.
			if v := a.argVal(st, arg, false); a.hits(v) && !v.weak {
				for _, l := range s.sink[k] {
					a.report(l)
				}
			}
		}
	}
}

// libParams taints the parameters of a public function in library mode.
func (a *analysis) libParams(f *fn, x state) {
	if !a.lib || !f.public || f.name == "" {
		return
	}
	fi := paramInfo(f, a.lang())
	for i, p := range fi.params {
		if p != "" && !fi.numeric[i] {
			x[p] = entry{taint: true}
		}
	}
}
