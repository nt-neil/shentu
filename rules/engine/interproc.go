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
// A call resolves to a summary when it names a function or a variable a
// closure was assigned to ($cb = function ...; $cb($x)), or a method: through
// $this->, self::, static::, this. or Python's self./cls. in the class the call
// is in (then up its parents in the file), parent:: from the parent, ClassName::
// of a class of the file. Arguments map to parameters by position, and by name
// for PHP named and Python keyword arguments.
//
// Summaries are computed when a call first needs them: once with the rule's
// sources (does the function return input of its own?), and with the sources
// off and the parameters tainted, all at once and, when that reaches anything,
// one at a time. Recursion is resolved by recomputing the summary at the head of
// the cycle until it no longer changes; the summaries of the other members are
// thrown away and recomputed each round, so none is kept from a stale round.
// Depth, the number of runs per rule and file, the rounds and the parameters
// are capped; a file that hits a cap is reported with ErrLimit, as for any other
// limit, and an argument past the parameter cap counts as passed on.

const (
	maxSumParams = 64   // parameters a summary tracks
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
	rest    bool     // takes any further arguments (...$a, *args, **kwargs)
}

type summary struct {
	params  []string            // the parameters' names, for named arguments
	rest    bool                // the function takes further arguments
	sink    [maxSumParams][]int // per parameter: the sink lines it reaches
	sinkEmb uint64              // parameters embedded in a larger string on the way to a sink
	ret     uint64              // parameters whose input the return value carries
	retWeak uint64              // ... only through calls the analysis does not know
	retEmb  uint64              // ... embedded in a larger string
	retSrc  bool                // the return value carries input of its own
}

func (s *summary) equal(o *summary) bool {
	if s.ret != o.ret || s.retSrc != o.retSrc || s.retEmb != o.retEmb || s.retWeak != o.retWeak || s.sinkEmb != o.sinkEmb {
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
	funcs   map[string][]*fnInfo // by name for functions, by "Class::name" for methods
	parents map[string]string    // class → parent, for classes of the file
	done    map[string]*summary
	busy    map[string]bool
	again   map[string]bool  // a call reached the name while its summary was being computed
	rel     map[string]uint8 // relevance to the rule: 0 not known yet, 1 yes, 2 no, 3 being worked out
	relPart bool             // a relevance check met one still being worked out
	order   []string         // summaries in the order they were finished
	runs    int
	depth   int
}

func newSummaries(funcs map[string][]*fnInfo) *summaries {
	if len(funcs) == 0 {
		return nil
	}
	sc := &summaries{funcs: funcs, parents: map[string]string{}, done: map[string]*summary{}, busy: map[string]bool{},
		again: map[string]bool{}, rel: map[string]uint8{}}
	for _, infos := range funcs {
		for _, fi := range infos {
			if fi.f.class != "" && fi.f.parent != "" {
				sc.parents[fi.f.class] = fi.f.parent
			}
		}
	}
	return sc
}

// summRun collects what one analysis of a function body found.
type summRun struct {
	lines map[int]bool
	emb   map[int]bool // lines reached by input embedded in a larger string
	ret   val
}

// funcKey is the key of a function in summaries.funcs.
func funcKey(f *fn, name string) string {
	if f.method && f.class != "" {
		return f.class + "::" + name
	}
	return name
}

// collectFuncs finds the named functions of a file, and closures assigned to a
// plain name.
func collectFuncs(ss []*stmt, lang string) map[string][]*fnInfo {
	out := map[string][]*fnInfo{}
	var walk func(ss []*stmt, depth int)
	add := func(name string, f *fn) {
		if name != "" && f != nil {
			k := funcKey(f, name)
			out[k] = append(out[k], paramInfo(f, lang))
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
				if tk.op("...") {
					fi.rest = true
				}
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
				p, fi.rest = p[1:], true
			}
			if len(p) > 0 && p[0].Kind == Ident {
				name = p[0].Text
			}
			if c := indexTop(p, 0, isOp(":")); c > 0 && c+1 < len(p) && p[c+1].Kind == Ident {
				numeric = numericCasts[p[c+1].Text] || p[c+1].Text == "int" || p[c+1].Text == "float"
			}
		case "js":
			if len(part) > 0 && part[0].op("...") {
				fi.rest = true
			}
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
var receivers = map[string]bool{"$this": true, "self": true, "static": true, "this": true, "cls": true}

// calleeKey returns the summaries key a call reaches, when t[i] is the name of
// a call (t[i+1] is "(") to a function or method of this file, else "".
func (a *analysis) calleeKey(t []Token, i int) string {
	if a.sc == nil || i+1 >= len(t) || !t[i+1].op("(") || t[i].Kind != Ident && !(a.php && t[i].Kind == Var) {
		return ""
	}
	name := t[i].Text
	if i > 0 && memberOp(a.php, t[i-1]) {
		if t[i].Kind != Ident || i < 2 || i > 2 && (memberOp(a.php, t[i-3]) || t[i-3].op("\\")) {
			return ""
		}
		switch r := t[i-2].Text; {
		case receivers[r]:
			return a.methodKey(a.cls, name)
		case r == "parent":
			return a.methodKey(a.parent, name)
		case t[i-2].Kind == Ident && a.sc.hasClass(r):
			return a.methodKey(r, name) // ClassName::m() of a class of this file
		}
		return ""
	}
	if i > 0 && (t[i-1].word("function") || t[i-1].word("def") || t[i-1].word("new") || t[i-1].word("fn") || a.php && t[i-1].op("\\")) {
		return ""
	}
	if len(a.sc.funcs[name]) == 0 {
		return ""
	}
	return name
}

// methodKey finds method name in class or, going up, in its parents in this file.
func (a *analysis) methodKey(class, name string) string {
	for depth := 0; class != "" && depth < 8; depth++ {
		if k := class + "::" + name; len(a.sc.funcs[k]) > 0 {
			return k
		}
		class = a.sc.parents[class]
	}
	return ""
}

func (sc *summaries) hasClass(c string) bool {
	if _, ok := sc.parents[c]; ok {
		return true
	}
	for k := range sc.funcs {
		if strings.HasPrefix(k, c+"::") {
			return true
		}
	}
	return false
}

// summaryOf returns the summary of a function of this file, computing it first
// if needed; nil when the key names none, or while it is being computed.
func (a *analysis) summaryOf(key string) *summary {
	sc := a.sc
	if sc == nil || key == "" {
		return nil
	}
	if s, ok := sc.done[key]; ok {
		return s
	}
	infos := sc.funcs[key]
	if len(infos) == 0 || !a.relevant(key) {
		return nil
	}
	if sc.busy[key] {
		sc.again[key] = true
		return nil
	}
	if sc.depth >= maxSumDepth || sc.runs >= maxSumRuns || a.b.hit {
		a.b.tooDeep()
		return nil
	}
	sc.busy[key] = true
	sc.depth++
	start := len(sc.order)
	forget := func() { // summaries finished during this computation may have used a stale one of key
		for _, k := range sc.order[start:] {
			delete(sc.done, k)
		}
		sc.order = sc.order[:start]
	}
	var s *summary
	for round := 0; ; round++ {
		delete(sc.again, key)
		n := &summary{}
		for _, fi := range infos {
			a.summarize(fi, n)
		}
		stable := s != nil && n.equal(s)
		s = n
		if stable || !sc.again[key] {
			break
		}
		if round+1 >= maxSumRounds {
			a.b.tooDeep() // a recursive cycle that does not settle
			forget()
			break
		}
		forget()
		sc.done[key] = s // the next round sees this one
	}
	sc.done[key] = s
	sc.order = append(sc.order, key)
	delete(sc.busy, key)
	sc.depth--
	return s
}

// relevant reports whether a function can matter to the rule: its body holds
// one of the rule's sources, sinks or sanitizers (or a number conversion), or
// calls a function of the file that does. The others keep the default (the
// result carries any argument's input), which spares analysing every function
// of a large file for every rule. A function found irrelevant only because a
// callee was still being worked out is checked again later.
func (a *analysis) relevant(key string) bool {
	sc := a.sc
	switch sc.rel[key] {
	case 1:
		return true
	case 2:
		return false
	case 3:
		sc.relPart = true
		return false
	}
	sc.rel[key] = 3
	outer := sc.relPart
	sc.relPart = false
	ok := false
	for _, fi := range sc.funcs[key] {
		if a.bodyRelevant(fi.f.body, 0) {
			ok = true
			break
		}
	}
	switch {
	case ok:
		sc.rel[key] = 1
	case sc.relPart:
		sc.rel[key] = 0
	default:
		sc.rel[key] = 2
	}
	sc.relPart = outer || !ok && sc.relPart
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
		if k := a.calleeKey(t, i); k != "" && a.relevant(k) {
			return true
		}
	}
	return false
}

// summarize adds what fi does to s.
func (a *analysis) summarize(fi *fnInfo, s *summary) {
	if s.params == nil {
		s.params = fi.params
	}
	s.rest = s.rest || fi.rest
	n := min(len(fi.params), maxSumParams)
	if len(fi.params) > maxSumParams {
		a.b.tooDeep() // more parameters than a summary tracks: the rest count as passed on (callVal)
	}
	run := func(mask uint64, sources bool) *summRun {
		x := &analysis{r: a.r, php: a.php, py: a.py, js: a.js, b: a.b, kw: a.kw, seen: map[int]bool{}, sc: a.sc,
			summ: &summRun{lines: map[int]bool{}, emb: map[int]bool{}}, noSrc: !sources, cls: fi.f.class, parent: fi.f.parent}
		st := state{}
		for i := 0; i < n; i++ {
			if p := fi.params[i]; p != "" && mask&(1<<i) != 0 {
				st[p] = entry{taint: true}
			}
		}
		a.sc.runs++
		x.block(fi.f.body, st)
		return x.summ
	}
	// With the rule's sources and no parameter: input of its own. Only input
	// returned as is counts (sanitize_locale_name($_GET['l']) is left out, as it
	// was before calls were followed).
	if base := run(0, true); base.ret.taint && !base.ret.weak {
		s.retSrc = true
	}
	if n == 0 || a.b.hit {
		return
	}
	// With the sources off, whatever reaches a sink or the return came from a parameter.
	if all := run(1<<n-1, false); len(all.lines) == 0 && !all.ret.taint {
		return
	}
	for i := 0; i < n && !a.b.hit; i++ {
		if fi.params[i] == "" {
			continue
		}
		r := run(1<<i, false)
		for l := range r.lines {
			if !slices.Contains(s.sink[i], l) {
				s.sink[i] = append(s.sink[i], l)
			}
			if r.emb[l] {
				s.sinkEmb |= 1 << i
			}
		}
		slices.Sort(s.sink[i])
		if r.ret.taint {
			s.ret |= 1 << i
			if r.ret.weak {
				s.retWeak |= 1 << i
			}
			if r.ret.emb {
				s.retEmb |= 1 << i
			}
		}
	}
}

// callArgs returns the arguments of the call whose "(" is at open.
func callArgs(t []Token, open int) [][]Token {
	c := closeOf(t, open)
	if c <= open {
		return nil
	}
	return splitTop(inside(t, open, c), isComma)
}

// argIndex maps a call's arguments to the callee's parameters: by position, or
// by name for PHP named (q: $x) and Python keyword (q=x) arguments. -1 means
// the argument reaches no known parameter (a spread, a name the callee does not
// declare, a position past the cap).
func (a *analysis) argIndex(s *summary, args [][]Token) []int {
	out := make([]int, len(args))
	pos := 0
	for k, arg := range args {
		out[k] = -1
		switch {
		case len(arg) > 0 && (arg[0].op("...") || arg[0].op("*") || arg[0].op("**")):
		case len(arg) > 1 && arg[0].Kind == Ident && (a.php && arg[1].op(":") || a.py && arg[1].op("=")):
			name := arg[0].Text
			if a.php {
				name = "$" + name
			}
			if i := slices.Index(s.params, name); i >= 0 && i < maxSumParams {
				out[k] = i
			}
		default:
			if pos < len(s.params) && pos < maxSumParams {
				out[k] = pos
			}
			pos++
		}
	}
	return out
}

// callVal is the value of a call to a summarised function. An argument that
// reaches no known parameter counts as passed on, as for an unknown function.
func (a *analysis) callVal(st state, s *summary, args [][]Token) val {
	v := val{taint: s.retSrc}
	for k, i := range a.argIndex(s, args) {
		if i >= 0 && s.ret&(1<<i) == 0 {
			continue
		}
		av := a.argVal(st, args[k], false)
		if !av.taint {
			continue
		}
		weak, emb := av.weak, av.emb
		if i >= 0 {
			weak = weak || s.retWeak&(1<<i) != 0
			emb = emb || s.retEmb&(1<<i) != 0
		} else if !s.rest && len(s.params) <= maxSumParams {
			weak = true // a name the function does not declare: nothing of it is used
		}
		v.weak = weakOf(v.taint, v.weak, true, weak)
		v.taint, v.emb = true, v.emb || emb
	}
	return v
}

// callSinks reports the sinks a call reaches through the callee's parameters.
func (a *analysis) callSinks(st state, t []Token) {
	if a.sc == nil {
		return
	}
	for i := 0; i+1 < len(t); i++ {
		s := a.summaryOf(a.calleeKey(t, i))
		if s == nil || !s.reachesSink() {
			continue
		}
		args := callArgs(t, i+1)
		for k, p := range a.argIndex(s, args) {
			if p < 0 || len(s.sink[p]) == 0 {
				continue
			}
			// Only input that did not come through an unknown call crosses into
			// another function's sinks: get_post($_GET['id']) is not the input.
			// In library mode the parameter may be embedded inside the callee.
			v := a.argVal(st, args[k], false)
			emb := v.emb || s.sinkEmb&(1<<p) != 0
			if v.taint && !v.weak && (!a.lib || emb) {
				for _, l := range s.sink[p] {
					a.reportSink(l, emb)
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
