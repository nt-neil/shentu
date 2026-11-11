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
	maxSumHeight = 128  // the longest chain of summaries under one: past it the summary counts as cut short
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
	params     []string // the parameters' names, for named arguments
	rest       bool     // the function takes further arguments
	sink       [][]loc  // per parameter: the sink lines it reaches, in this or another file (up to the last that reaches one)
	sinkEmb    uint64   // parameters embedded in a larger string on the way to a sink
	ret        uint64   // parameters whose input the return value carries
	retWeak    uint64   // ... only through calls the analysis does not know
	retEmb     uint64   // ... embedded in a larger string
	checks     uint64   // parameters the function validates when it returns true (a validator)
	condChecks uint64   // ... only where the call's other arguments carry no input (the list may be one)
	retSrc     bool     // the return value carries input of its own
	capped     bool     // a cap of its own work cut it short: what it says may be too little
	height     int      // the longest chain of summaries under it, itself included
	cost       int      // its own work, not its callees': what an asker pays for using it
	id         string   // file and key: the same summary worked out again (after a cache let it go) is paid for once
}

func (s *summary) equal(o *summary) bool {
	if s.ret != o.ret || s.retSrc != o.retSrc || s.retEmb != o.retEmb || s.retWeak != o.retWeak || s.sinkEmb != o.sinkEmb || s.checks != o.checks || s.condChecks != o.condChecks {
		return false
	}
	for i := range max(len(s.sink), len(o.sink)) {
		if !slices.Equal(s.sinkOf(i), o.sinkOf(i)) {
			return false
		}
	}
	return true
}

// sinkOf is the sink lines parameter i reaches. A summary holds as many lists
// as it needs, not one per parameter it could track: there are a summary per
// rule and function, most reaching no sink at all.
func (s *summary) sinkOf(i int) []loc {
	if i < len(s.sink) {
		return s.sink[i]
	}
	return nil
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
	ff     *fileFuncs
	funcs  map[string][]*fnInfo // ff.byKey
	done   map[string]*summary
	busy   map[string]bool
	rel    map[string]uint8     // relevance to the rule, once known: 1 yes, 2 no (relevance.go)
	direct map[string]bool      // what in the function itself matters to the rule, calls aside; nil until worked out
	cross  map[string][]relNode // the functions of other files the function calls
	retUnk map[string]uint8     // 1: the function returns the result of a call the analysis does not know; 2: it does not
	capped bool                 // a summary hit a cap (depth, runs, rounds, parameters) and may say too little
	runs   int
	depth  int
}

func newSummaries(ff *fileFuncs) *summaries {
	if ff == nil || len(ff.byKey) == 0 {
		return nil
	}
	return &summaries{ff: ff, funcs: ff.byKey, done: map[string]*summary{}, busy: map[string]bool{},
		rel: map[string]uint8{}, retUnk: map[string]uint8{}}
}

// fileFuncs are the named functions of a file and how they call one another,
// shared by every rule's summaries.
type fileFuncs struct {
	php      bool
	byKey    map[string][]*fnInfo // by name for functions, by "Class::name" for methods (PHP: lower case)
	parents  map[string]string    // class → parent
	traits   map[string][]string  // class → PHP traits it uses
	comp     map[string]int       // key → its strongly connected component of the call graph
	comps    [][]string
	edges    map[string][]string // key → the keys it calls
	callers  map[string][]string // key → the keys that call it
	unions   map[string][]string // a $this union key → the keys it merges
	classSet map[string]bool     // classes of the file, worked out once
	methods  map[string]string   // memo of method(): class + "\x00" + name → key
	desc     map[string][]string // class → the classes of the file under it, worked out once
	callsUp  map[string]bool     // memo of callsParent(): key + "\x00" + name
}

func newFileFuncs(funcs map[string][]*fnInfo, lang string) *fileFuncs {
	ff := &fileFuncs{php: lang == "php", byKey: funcs, parents: map[string]string{}, traits: map[string][]string{}}
	for _, infos := range funcs {
		for _, fi := range infos {
			if c := fi.f.class; c != "" {
				c = ff.norm(c)
				if fi.f.parent != "" {
					ff.parents[c] = ff.norm(fi.f.parent)
				}
				for _, t := range fi.f.traits {
					if t = ff.norm(t); !slices.Contains(ff.traits[c], t) {
						ff.traits[c] = append(ff.traits[c], t)
					}
				}
			}
		}
	}
	return ff
}

// norm is a class name as keys use it: without namespace, PHP in lower case.
func (ff *fileFuncs) norm(c string) string {
	c = c[strings.LastIndexAny(c, `\.`)+1:]
	if ff.php {
		c = strings.ToLower(c)
	}
	return c
}

// summRun collects what one analysis of a function body found.
type summRun struct {
	lines  map[loc]bool
	emb    map[loc]bool      // lines reached by input embedded in a larger string
	checks []map[string]bool // per return that can be true: the paths it validates
	ret    val
}

// funcKey is the key of a function in fileFuncs.byKey. PHP function, method
// and class names do not depend on case; a closure's $variable does.
func funcKey(f *fn, name, lang string) string {
	low := func(x string) string {
		if lang == "php" && !strings.HasPrefix(x, "$") {
			return strings.ToLower(x)
		}
		return x
	}
	if f.method && f.class != "" {
		c := f.class[strings.LastIndexAny(f.class, `\.`)+1:]
		return low(c) + "::" + low(name)
	}
	return low(name)
}

// collectFuncs finds the named functions of a file, and closures assigned to a
// plain name.
func collectFuncs(ss []*stmt, lang string) map[string][]*fnInfo {
	out := map[string][]*fnInfo{}
	var walk func(ss []*stmt, depth int)
	add := func(name string, f *fn) {
		if name != "" && f != nil {
			k := funcKey(f, name, lang)
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
				} else if n := len(t); n >= 5 && t[n-1].Kind == Func && t[n-1].Fn < len(s.funcs) && t[n-2].op("=") && t[n-3].Kind == Ident && dotted(t[:n-2]) {
					add(t[n-3].Text, s.funcs[t[n-1].Fn]) // exports.f = function, module.exports.f = (x) => ...
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

// dotted reports whether t is a plain dotted name (a.b.c).
func dotted(t []Token) bool {
	for i, tk := range t {
		if i%2 == 0 && tk.Kind != Ident || i%2 == 1 && !tk.op(".") {
			return false
		}
	}
	return len(t)%2 == 1
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

// calleeKey returns the summaries key a call reaches, when t[i] is the name of
// a call (t[i+1] is "(") to a function or method of this file, else "".
func (a *analysis) calleeKey(t []Token, i int) string {
	if a.sc == nil {
		return ""
	}
	return a.sc.ff.key(t, i, a.cls, a.parent, a.fname)
}

// key resolves the call named at t[i] from method caller of class cls (with parent).
func (ff *fileFuncs) key(t []Token, i int, cls, parent, caller string) string {
	if i+1 >= len(t) || !t[i+1].op("(") || t[i].Kind != Ident && !(ff.php && t[i].Kind == Var) {
		return ""
	}
	name := t[i].Text
	if ff.php && t[i].Kind == Ident {
		name = strings.ToLower(name)
	}
	if i > 0 && memberOp(ff.php, t[i-1]) {
		if t[i].Kind != Ident || i < 2 {
			return ""
		}
		// super().q(), Python; super.q(), JavaScript.
		if i >= 4 && t[i-2].op(")") && t[i-3].op("(") && t[i-4].word("super") || t[i-2].word("super") {
			return ff.method(ff.norm(parent), name, 0)
		}
		if i > 2 && (memberOp(ff.php, t[i-3]) || t[i-3].op(`\`)) {
			return ""
		}
		switch r := t[i-2].Text; {
		case ff.php && strings.EqualFold(r, "self"):
			return ff.method(ff.norm(cls), name, 0) // self:: is the class the code is in
		case receivers[r] || ff.php && strings.EqualFold(r, "static"):
			return ff.this(ff.norm(cls), name, caller) // $this, static::, this, self, cls: the object's class may be a subclass
		case ff.php && strings.EqualFold(r, "parent"):
			return ff.method(ff.norm(parent), name, 0)
		case t[i-2].Kind == Ident && ff.hasClass(ff.norm(r)):
			return ff.method(ff.norm(r), name, 0) // ClassName::m() of a class of this file
		}
		return ""
	}
	if i > 0 && (t[i-1].word("function") || t[i-1].word("def") || t[i-1].word("new") || t[i-1].word("fn") || ff.php && t[i-1].op(`\`)) {
		return ""
	}
	if len(ff.byKey[name]) == 0 {
		return ""
	}
	return name
}

// callee is the function a call names, for resolving it in another file: name,
// and how it is reached. recv is "" for a plain call, "this" for the object's
// own class, "parent" for parent::/super, and otherwise the receiver as
// written (Foo::, $mailer->, module.).
type callee struct{ name, recv string }

func (a *analysis) callee(t []Token, i int) (callee, bool) {
	if i+1 >= len(t) || !t[i+1].op("(") || t[i].Kind != Ident && !(a.php && t[i].Kind == Var) {
		return callee{}, false
	}
	if i > 0 && memberOp(a.php, t[i-1]) {
		if t[i].Kind != Ident || i < 2 {
			return callee{}, false
		}
		if i >= 4 && t[i-2].op(")") && t[i-3].op("(") && t[i-4].word("super") || t[i-2].word("super") {
			return callee{t[i].Text, "parent"}, true
		}
		if a.php && i > 2 && t[i-1].op("::") && t[i-2].Kind == Ident && t[i-3].op(`\`) { // \App\Users::find()
			j := i - 2 // back over Name\Name\..., names and backslashes in turn: return App\Run:: is App\Run
			for j >= 2 && t[j-1].op(`\`) && t[j-2].Kind == Ident {
				j -= 2
			}
			if j >= 1 && t[j-1].op(`\`) {
				j-- // \App\Run, fully qualified
			}
			if j > 0 && memberOp(true, t[j-1]) {
				return callee{}, false
			}
			var q strings.Builder
			for _, tk := range t[j : i-1] {
				q.WriteString(tk.Text)
			}
			return callee{t[i].Text, q.String()}, true
		}
		if i > 2 && (memberOp(a.php, t[i-3]) || t[i-3].op("\\")) || t[i-2].Kind != Ident && t[i-2].Kind != Var {
			return callee{}, false
		}
		r := t[i-2].Text
		switch {
		case a.php && strings.EqualFold(r, "parent"):
			r = "parent"
		case receivers[r] || a.php && (strings.EqualFold(r, "self") || strings.EqualFold(r, "static")):
			r = "this"
		}
		return callee{t[i].Text, r}, true
	}
	if i > 0 && (t[i-1].word("function") || t[i-1].word("def") || t[i-1].word("new") || t[i-1].word("fn")) {
		return callee{}, false
	}
	return callee{t[i].Text, ""}, true
}

// callSummary returns the summary of the function the call at t[i] reaches: the
// one of this file at key, or, when there is none, one of another file of the
// project.
func (a *analysis) callSummary(t []Token, i int, key string) *summary {
	if key != "" {
		return a.summaryOf(key)
	}
	if a.proj == nil {
		return nil
	}
	if c, ok := a.callee(t, i); ok {
		return a.proj.summary(a, c)
	}
	return nil
}

// receivers are the objects through which a call reaches a method of the
// object's own class (PHP's static:: and self:: are handled apart).
var receivers = map[string]bool{"$this": true, "this": true, "self": true, "cls": true}

// method finds method name in class, its traits, or, going up, its parents.
// Each class is visited once per lookup, and lookups are remembered.
func (ff *fileFuncs) method(class, name string, _ int) string {
	if class == "" {
		return ""
	}
	mk := class + "\x00" + name
	if k, ok := ff.methods[mk]; ok {
		return k
	}
	seen := map[string]bool{}
	var find func(c string) string
	find = func(c string) string {
		if c == "" || seen[c] || len(seen) > 64 {
			return ""
		}
		seen[c] = true
		if k := c + "::" + name; len(ff.byKey[k]) > 0 {
			return k
		}
		for _, tr := range ff.traits[c] {
			if k := find(tr); k != "" {
				return k
			}
		}
		return find(ff.parents[c])
	}
	k := find(class)
	if ff.methods == nil {
		ff.methods = map[string]string{}
	}
	ff.methods[mk] = k
	return k
}

// this resolves $this->name() in method caller of class: the method the class
// has, merged with the overrides of its subclasses in the file, since $this may
// be one of them; not those that override caller too (for them this code does
// not run).
func (ff *fileFuncs) this(class, name, caller string) string {
	base := ff.method(class, name, 0)
	if ff.php {
		caller = strings.ToLower(caller)
	}
	var subs []string
	for _, c := range ff.descendants()[class] {
		if caller != "" && len(ff.byKey[c+"::"+caller]) > 0 && !ff.callsParent(c+"::"+caller, caller) {
			continue // c overrides the calling method and never runs it
		}
		if k := c + "::" + name; len(ff.byKey[k]) > 0 && k != base {
			subs = append(subs, k)
		}
	}
	if len(subs) == 0 {
		return base
	}
	slices.Sort(subs)
	vk := "$this " + class + "::" + name + " " + strings.Join(subs, ",") // a key of its own for the union
	if _, ok := ff.byKey[vk]; !ok {
		var infos []*fnInfo
		if base != "" {
			infos = append(infos, ff.byKey[base]...)
		}
		for _, k := range subs {
			infos = append(infos, ff.byKey[k]...)
		}
		ff.byKey[vk] = infos
		if ff.unions == nil {
			ff.unions = map[string][]string{}
		}
		if base != "" {
			ff.unions[vk] = append(ff.unions[vk], base)
		}
		ff.unions[vk] = append(ff.unions[vk], subs...)
	}
	return vk
}

// descendants maps each class to the classes of the file that inherit it
// (up to 64 parents up), so that $this->name() is resolved without
// going over every class of the file each time.
func (ff *fileFuncs) descendants() map[string][]string {
	if ff.desc != nil {
		return ff.desc
	}
	ff.desc = map[string][]string{}
	for c := range ff.classes() {
		a := c
		for depth := 0; a != "" && depth < 64; depth++ {
			if a = ff.parents[a]; a != "" && a != c && (len(ff.desc[a]) == 0 || ff.desc[a][len(ff.desc[a])-1] != c) {
				ff.desc[a] = append(ff.desc[a], c) // once, also when the parents go round in a cycle
			}
		}
	}
	return ff.desc
}

// callsParent reports whether the method at key calls its parent's version
// (parent::name(), super().name(), super.name()), so the parent's code still runs.
// It is worked out once per method: $this->name() asks it for every call.
func (ff *fileFuncs) callsParent(key, name string) bool {
	mk := key + "\x00" + name
	if v, ok := ff.callsUp[mk]; ok {
		return v
	}
	if ff.callsUp == nil {
		ff.callsUp = map[string]bool{}
	}
	found := false
	for _, fi := range ff.byKey[key] {
		walkToks(fi.f.body, 0, func(t []Token) {
			for i := 2; i+1 < len(t) && !found; i++ {
				if !t[i+1].op("(") || !memberOp(ff.php, t[i-1]) || !strings.EqualFold(t[i].Text, name) {
					continue
				}
				found = t[i-2].word("super") || ff.php && strings.EqualFold(t[i-2].Text, "parent") ||
					i >= 4 && t[i-2].op(")") && t[i-3].op("(") && t[i-4].word("super")
			}
		})
	}
	ff.callsUp[mk] = found
	return found
}

func (ff *fileFuncs) classes() map[string]bool {
	if ff.classSet != nil {
		return ff.classSet
	}
	out := map[string]bool{}
	for k := range ff.byKey {
		if i := strings.Index(k, "::"); i > 0 && !strings.HasPrefix(k, "$this ") {
			out[k[:i]] = true
		}
	}
	for c := range ff.parents {
		out[c] = true
	}
	ff.classSet = out
	return out
}

func (ff *fileFuncs) hasClass(c string) bool { return ff.classes()[c] }

// components computes the strongly connected components of the call graph
// (Tarjan), so that mutually recursive functions are summarised together. The
// tokens it reads are charged to b.
func (ff *fileFuncs) components(b *budget) {
	if ff.comp != nil {
		return
	}
	ff.comp = map[string]int{}
	edges := map[string][]string{}
	ff.edges, ff.callers = edges, map[string][]string{}
	keys := make([]string, 0, len(ff.byKey))
	for k := range ff.byKey {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		seen := map[string]bool{}
		for _, fi := range ff.byKey[k] {
			walkToks(fi.f.body, 0, func(t []Token) {
				if !b.charge(len(t)) {
					return
				}
				for i := range t {
					if c := ff.key(t, i, fi.f.class, fi.f.parent, fi.f.name); c != "" && !seen[c] {
						seen[c] = true
						edges[k] = append(edges[k], c)
						ff.callers[c] = append(ff.callers[c], k)
					}
				}
			})
		}
	}
	if b.hit { // the clock ran out: no partial graph is kept
		ff.comp, ff.edges, ff.callers = nil, nil, nil
		return
	}
	index, low, onStack := map[string]int{}, map[string]int{}, map[string]bool{}
	var stack []string
	n := 0
	var strong func(v string)
	strong = func(v string) {
		index[v], low[v] = n, n
		n++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range edges[v] {
			if _, ok := index[w]; !ok {
				strong(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] == index[v] {
			var c []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				ff.comp[w] = len(ff.comps)
				c = append(c, w)
				if w == v {
					break
				}
			}
			if len(c) == 1 && !slices.Contains(edges[v], v) {
				ff.comp[v] = -1 // not recursive
			} else {
				ff.comps = append(ff.comps, c)
			}
		}
	}
	for _, k := range keys {
		if _, ok := index[k]; !ok {
			strong(k)
		}
	}
}

// walkToks calls f with the tokens of every statement under ss.
func walkToks(ss []*stmt, depth int, f func([]Token)) {
	if depth > maxNest {
		return
	}
	for _, s := range ss {
		f(s.toks)
		for _, fn := range s.funcs {
			walkToks(fn.body, depth+1, f)
		}
		if s.fn != nil && s.fn.name == "" {
			walkToks(s.fn.body, depth+1, f)
		}
		walkToks(s.body, depth+1, f)
		walkToks(s.els, depth+1, f)
		walkToks(s.orelse, depth+1, f)
		for _, h := range s.handlers {
			walkToks(h, depth+1, f)
		}
		for _, c := range s.cases {
			walkToks(c, depth+1, f)
		}
	}
}

// summaryOf returns the summary of a function of this file, computing it first
// if needed; nil when the key names none or the function does not matter to the
// rule. A recursive function is summarised with the rest of its strongly
// connected component: all start from an empty summary and are recomputed in
// turn until none changes (a worklist fixpoint, at most maxSumRounds rounds).
func (a *analysis) summaryOf(key string) *summary {
	sc := a.sc
	if sc == nil || key == "" {
		return nil
	}
	if s, ok := sc.done[key]; ok {
		return a.used(s)
	}
	if s := a.proj.provisional(sc, key); s != nil {
		return a.used(s) // a member of a cycle across files still being settled
	}
	if len(sc.funcs[key]) == 0 || !a.relevant(key) || sc.busy[key] {
		return nil
	}
	if a.b.hit {
		a.b.tooDeep()
		return nil
	}
	if !a.graph() {
		return nil
	}
	c, ok := sc.ff.comp[key]
	if !ok || c < 0 {
		sc.busy[key] = true
		idx := a.proj.push(a, []string{key})
		var s *summary
		capped, keep, height, cost := a.own(func(x *analysis) { s = x.summarizeKey(key) })
		delete(sc.busy, key)
		fr := a.proj.pop()
		if s == nil { // nested too deep: not worked out
			return nil
		}
		s.capped, s.height, s.cost, s.id = capped, height, cost, a.file+"\x00"+key
		switch {
		case !keep:
			a.proj.drop(fr)
		case fr != nil && fr.root < idx: // part of a cycle across files whose first member is below
			a.proj.hold(fr, map[string]*summary{key: s})
		case fr != nil && len(fr.members) > 0: // the first member of a cycle across files: settle it
			return a.used(a.proj.settle(fr, key))
		default:
			sc.done[key] = s
		}
		return a.used(s)
	}
	var members []string
	for _, m := range sc.ff.comps[c] {
		if _, ok := sc.done[m]; !ok && a.relevant(m) {
			members = append(members, m)
			sc.done[m] = &summary{} // the fixpoint starts from "does nothing"
			sc.busy[m] = true       // another file asking for one meets a cycle
		}
	}
	idx := a.proj.push(a, members)
	capped, keep, height, cost := a.own(func(x *analysis) {
		for round := 0; ; round++ {
			changed := false
			for _, m := range members {
				if n := x.summarizeKey(m); !n.equal(sc.done[m]) {
					sc.done[m], changed = n, true
				}
			}
			if !changed || x.b.hit {
				break
			}
			if round+1 >= maxSumRounds {
				x.b.tooDeep() // a recursive cycle that does not settle
				break
			}
		}
	})
	fr := a.proj.pop()
	got := map[string]*summary{}
	for _, m := range members {
		delete(sc.busy, m)
		sc.done[m].capped, sc.done[m].height, sc.done[m].cost, sc.done[m].id = capped, height, cost, a.file+"\x00"+m
		got[m] = sc.done[m]
	}
	s := sc.done[key]
	switch {
	case !keep:
		for _, m := range members {
			delete(sc.done, m)
		}
		a.proj.drop(fr)
	case fr != nil && fr.root < idx:
		for _, m := range members {
			delete(sc.done, m)
		}
		a.proj.hold(fr, got)
	case fr != nil && len(fr.members) > 0:
		s = a.proj.settle(fr, key)
	}
	return a.used(s)
}

// used returns a summary to the analysis that asked for it: one a cap cut
// short may say too little, so the asker's result says calls were not
// followed to the end, whether the summary was worked out now or before.
func (a *analysis) used(s *summary) *summary {
	if s != nil && s.capped {
		a.b.tooDeep()
	}
	// The asker pays what working it out cost, once, whether it was ready or
	// not: so its own caps fall at the same place either way, and a rule's
	// work in a file, summaries included, stays within its cap.
	if s != nil && s.cost > 0 && !a.b.charged[s.id] {
		if a.b.charged == nil {
			a.b.charged = map[string]bool{}
		}
		a.b.charged[s.id] = true
		a.b.paid += s.cost
		a.b.charge(s.cost)
	}
	if s != nil && a.heights != nil && s.height > *a.heights {
		*a.heights = s.height
	}
	return s
}

// maxOwnNest bounds summaries worked out inside one another (a chain of calls
// none of which has its summary yet); past it a summary is not worked out.
// It is twice maxSumHeight: a chain that deep is cut by its height whichever
// summaries were ready.
const maxOwnNest = 2 * maxSumHeight

// own works out a summary in a budget and a nesting of its own, not the
// asker's: the same summary comes out whoever asks for it and whatever was
// worked out before, so a summary kept and used later is the one any later
// asker would have worked out, and what the asker's caps cut does not depend
// on which summaries it found ready. capped tells whether the summary's own
// caps cut it short (said by the summary itself, see used); keep is false
// when it cannot be kept: cut by the clock, or nested too deep.
func (a *analysis) own(work func(x *analysis)) (capped, keep bool, height, cost int) {
	sc := a.sc
	if a.nest >= maxOwnNest {
		a.b.tooDeep()
		return true, false, 0, 0
	}
	nb := &budget{maxTok: a.b.maxTok, deadline: a.b.deadline, maxWork: a.b.sumWork, sumWork: a.b.sumWork}
	under := 0 // the highest summary this one uses
	depth, runs, was := sc.depth, sc.runs, sc.capped
	sc.depth, sc.runs, sc.capped = 0, 0, false
	pdepth := 0
	if a.proj != nil {
		pdepth, a.proj.depth = a.proj.depth, 0
	}
	x := *a
	x.b, x.nest, x.heights = nb, a.nest+1, &under
	work(&x)
	height, cost = under+1, nb.work-nb.paid // its own work: what it paid for its callees is theirs
	// A chain of summaries longer than maxSumHeight is cut: by the chain's own
	// length under this summary, which no asker changes. (The real chains are
	// much shorter: 45 at most in WordPress. A cap near them would make the
	// result depend on the scan order, as a chain through a cycle across files
	// is a step or two longer or shorter depending on where it was entered.)
	capped = sc.capped || nb.limited || nb.hit && !nb.timeHit || height > maxSumHeight
	sc.depth, sc.runs, sc.capped = depth, runs, was
	if a.proj != nil {
		a.proj.depth = pdepth
	}
	if nb.timeHit {
		// The clock: nothing to keep, and the asker is cut by it as well.
		if a.proj != nil {
			a.proj.stop("following calls across files ran out of time")
			a.proj.byMachine = true
		}
		a.b.hit, a.b.timeHit = true, true
		return capped, false, height, cost
	}
	return capped, true, height, cost
}

// graph builds the file's call graph, work kept for the whole file: charged to
// nobody, so that no asker pays for it more than another, but within the
// asker's clock. False when the clock ran out: the asker is cut by it as well,
// and the next asker builds the graph again.
func (a *analysis) graph() bool {
	b := &budget{maxTok: 1 << 40, deadline: a.b.deadline}
	a.sc.ff.components(b)
	if b.hit {
		a.b.hit, a.b.timeHit = true, true
		return false
	}
	return true
}

func (a *analysis) summarizeKey(key string) *summary {
	s := &summary{}
	for _, fi := range a.sc.funcs[key] {
		a.summarize(fi, s)
	}
	return s
}

// crossNeeded reports whether following calls can change the rule's result in
// this file: some function that matters to the rule is called (by another
// function, or by the file's top-level code). Otherwise the analysis inside
// each function is the whole answer.
func (a *analysis) crossNeeded(tree []*stmt) bool {
	sc := a.sc
	if sc == nil {
		return false
	}
	if !a.graph() {
		return false
	}
	keys := make([]string, 0, len(sc.funcs))
	for k := range sc.funcs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if len(sc.ff.callers[k]) > 0 && a.relevant(k) {
			return true
		}
	}
	found := false
	look := func(t []Token) {
		for i := 0; i < len(t) && !found; i++ {
			if k := sc.ff.key(t, i, "", "", ""); k != "" && a.relevant(k) {
				found = true
			} else if k == "" && a.proj != nil && i+1 < len(t) && t[i+1].op("(") && t[i].Kind == Ident &&
				(a.proj.declaredElsewhere(a.lang(), t[i].Text, a.file) || a.proj.importedRelative(a.file, t, i)) {
				found = true // may call into another file of the project (types are known only later)
			}
		}
	}
	walkToks(tree, 0, look)
	if a.proj != nil {
		for _, infos := range sc.funcs { // and inside the file's functions, for calls into other files
			for _, fi := range infos {
				if !found {
					walkToks(fi.f.body, 0, look)
				}
			}
		}
	}
	return found
}

// returnsUnknown reports whether input a function passes on comes back only
// through calls the analysis does not know ($p = get_post($id); return $p):
// it is a guess, as with the call written out. It follows the data: the body is
// read once with the parameters tainted and the rule's sources off, and the
// return value is a guess unless it carries a parameter as is.
func (a *analysis) returnsUnknown(key string) bool {
	sc := a.sc
	switch sc.retUnk[key] {
	case 1:
		return true
	case 2:
		return false
	}
	sc.retUnk[key] = 1
	for _, fi := range sc.funcs[key] {
		x := &analysis{r: a.r, php: a.php, py: a.py, js: a.js, b: a.b, kw: a.kw, seen: map[loc]bool{}, sc: sc,
			summ: &summRun{lines: map[loc]bool{}, emb: map[loc]bool{}}, noSrc: true, cls: fi.f.class, parent: fi.f.parent, fname: fi.f.name,
			file: a.file, proj: a.proj, ftoks: a.ftoks, rdefs: a.rdefs}
		st := state{}
		for _, p := range fi.params {
			if p != "" {
				st[p] = entry{taint: true}
			}
		}
		x.block(fi.f.body, st)
		if x.summ.ret.taint && !x.summ.ret.weak {
			sc.retUnk[key] = 2
		}
	}
	return sc.retUnk[key] == 1
}

// relevant reports whether a function can matter to the rule: its body holds
// one of the rule's sources, sinks or sanitizers (or a number conversion), or
// it calls, directly or not, a function of the file that does. The others keep
// the default (the result carries any argument's input), which spares
// analysing every function of a large file for every rule. It is worked out for
// all functions at once: each body is read once, and relevance goes back along
// the call graph to the callers.
// relevant reports whether the function key of a's file matters to the rule
// (relevance.go).
func (a *analysis) relevant(key string) bool {
	if key == "" {
		return false
	}
	return a.reach(relNode{a.file, key})
}

func (a *analysis) toksRelevant(t []Token) bool {
	if !a.b.charge(len(t)) {
		return true
	}
	if len(t) > 1 && t[0].word("return") { // a validator: return in_array($c, $cols, true);
		for _, tk := range t[1:] {
			if tk.Kind == Ident && checkWords[tk.Text] {
				return true
			}
		}
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
	}
	return false
}

// checkWords are calls a validator's return is commonly made of.
var checkWords = words("in_array array_key_exists preg_match ctype_digit ctype_alnum ctype_alpha is_numeric filter_var " +
	"fullmatch match includes has test startsWith")

// summarize adds what fi does to s.
func (a *analysis) summarize(fi *fnInfo, s *summary) {
	if s.params == nil {
		s.params = fi.params
	}
	s.rest = s.rest || fi.rest
	n := min(len(fi.params), maxSumParams)
	if len(fi.params) > maxSumParams {
		a.b.tooDeep() // more parameters than a summary tracks: the rest count as passed on (callVal)
		a.sc.capped = true
	}
	run := func(mask uint64, sources bool) *summRun {
		x := &analysis{r: a.r, php: a.php, py: a.py, js: a.js, b: a.b, kw: a.kw, seen: map[loc]bool{}, sc: a.sc, defs: a.defs,
			summ: &summRun{lines: map[loc]bool{}, emb: map[loc]bool{}}, noSrc: !sources, cls: fi.f.class, parent: fi.f.parent, fname: fi.f.name,
			file: a.file, proj: a.proj, ftoks: a.ftoks, rdefs: a.rdefs, nest: a.nest, heights: a.heights}
		st := state{}
		x.paramTypes(fi.f)
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
	base := run(0, true)
	if base.ret.taint && !base.ret.weak {
		s.retSrc = true
	}
	if n == 0 || a.b.hit {
		return
	}
	// A validator: every return that can be true checks the value the
	// parameter was given (return in_array($column, $columns, true);), so a
	// true result means the argument passed it. With every parameter tainted,
	// a check against a list another parameter brings does not count: such a
	// function validates only where the call passes clean other arguments
	// (condChecks).
	validates := func(r *summRun, i int) bool {
		ok := fi.params[i] != "" && len(r.checks) > 0
		for _, c := range r.checks {
			ok = ok && c[fi.params[i]]
		}
		return ok
	}
	// With the sources off, whatever reaches a sink or the return came from a parameter.
	all := run(1<<n-1, false)
	for i := 0; i < n; i++ {
		if validates(all, i) {
			s.checks |= 1 << i
		}
	}
	if len(all.lines) == 0 && !all.ret.taint && len(all.checks) == 0 {
		return
	}
	for i := 0; i < n && !a.b.hit; i++ {
		if fi.params[i] == "" {
			continue
		}
		r := run(1<<i, false)
		if s.checks&(1<<i) == 0 && validates(r, i) {
			s.condChecks |= 1 << i
		}
		for l := range r.lines {
			for len(s.sink) <= i {
				s.sink = append(s.sink, nil)
			}
			if !slices.Contains(s.sink[i], l) {
				s.sink[i] = append(s.sink[i], l)
			}
			if r.emb[l] {
				s.sinkEmb |= 1 << i
			}
		}
		slices.SortFunc(s.sinkOf(i), func(x, y loc) int {
			if x.path != y.path {
				return strings.Compare(x.path, y.path)
			}
			return x.line - y.line
		})
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
// by name for PHP named (q: $x) and Python keyword (q=x) arguments. anyParam
// marks an argument that may land in any parameter (a spread, *args, and every
// argument after one); noParam one that reaches none (a name the callee does
// not declare, a position past its parameters).
func (a *analysis) argIndex(s *summary, args [][]Token) []int {
	out := make([]int, len(args))
	pos, spread := 0, false
	for k, arg := range args {
		out[k] = noParam
		switch {
		case len(arg) > 0 && (arg[0].op("...") || arg[0].op("*")):
			spread = true
			out[k] = anyParam
		case len(arg) > 0 && arg[0].op("**"):
			out[k] = anyParam
		case len(arg) > 1 && arg[0].Kind == Ident && (a.php && arg[1].op(":") || a.py && arg[1].op("=")):
			name := arg[0].Text
			if a.php {
				name = "$" + name
			}
			if i := slices.Index(s.params, name); i >= 0 && i < maxSumParams {
				out[k] = i
			} else if s.rest {
				out[k] = anyParam
			}
		case spread:
			out[k] = anyParam
		default:
			switch {
			case pos < len(s.params) && pos < maxSumParams:
				out[k] = pos
			case s.rest || pos >= maxSumParams:
				out[k] = anyParam
			}
			pos++
		}
	}
	return out
}

const (
	noParam  = -1
	anyParam = -2
)

// callVal is the value of a call to a summarised function. An argument that
// may land in any parameter counts as passed on, as for an unknown function.
func (a *analysis) callVal(st state, s *summary, args [][]Token) val {
	v := val{taint: s.retSrc}
	for k, i := range a.argIndex(s, args) {
		if i >= 0 && s.ret&(1<<i) == 0 || i == noParam {
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
		}
		v.weak = weakOf(v.taint, v.weak, true, weak)
		v.taint, v.emb = true, v.emb || emb
	}
	return v
}

// callSinks reports the sinks a call reaches through the callee's parameters.
// jsonResponders send their argument as JSON and end the request.
var jsonResponders = map[string]bool{"wp_send_json": true, "wp_send_json_error": true, "wp_send_json_success": true}

func (a *analysis) callSinks(st state, t []Token) {
	if a.sc == nil && a.proj == nil {
		return
	}
	for i := 0; i+1 < len(t); i++ {
		s := a.callSummary(t, i, a.calleeKey(t, i))
		if s == nil || !s.reachesSink() {
			continue
		}
		// A JSON responder the rule lists as a sanitizer does not take its
		// arguments into its body's sinks: wp_send_json echoes, but as JSON, then
		// ends the request. Other sanitizer names (e, count) still do, so a helper
		// of the code base that only shares the name is followed as before.
		if jsonResponders[t[i].Text] {
			if _, _, _, ok := a.sanitizerAt(st, t, i); ok {
				continue
			}
		}
		args := callArgs(t, i+1)
		for k, p := range a.argIndex(s, args) {
			if p == noParam {
				continue
			}
			// Only input that did not come through an unknown call crosses into
			// another function's sinks: get_post($_GET['id']) is not the input.
			// In library mode the parameter may be embedded inside the callee.
			v := a.argVal(st, args[k], false)
			if !v.taint || v.weak {
				continue
			}
			for q := range s.sink {
				if p >= 0 && q != p || len(s.sink[q]) == 0 {
					continue
				}
				if emb := v.emb || s.sinkEmb&(1<<q) != 0; !a.lib || emb {
					for _, l := range s.sink[q] {
						a.reportSink(l, emb)
					}
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
