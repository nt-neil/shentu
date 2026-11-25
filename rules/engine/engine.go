// Package engine applies Shentu's code rules (package rules) to PHP, Python,
// JavaScript and TypeScript files (TypeScript uses the JavaScript rules). It lexes the file by hand, splits it into statements and
// function scopes, and follows user input inside each function in order: from a
// source, through variables, to a sink, unless a sanitizer or a check is in the
// way. Calls to functions of the same file follow their summaries
// (interproc.go); values are not followed across files.
//
// Findings name the rule, the file and the line, never the code itself:
// application code must not leave the host or be sent to an AI model.
package engine

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/rules"
)

// Finding is one place where a rule matched.
type Finding struct {
	RuleID   string `json:"rule"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	CWE      string `json:"cwe"`
	Fix      string `json:"fix"`
	Tier     string `json:"tier"` // the rule's tier: "info" or "alert"
	// Routes: the routes registering the handler the sink sits in, when the
	// file says so for certain (routerefs.go); absent otherwise.
	Routes []RouteRef `json:"routes,omitempty"`
	// RoutesTruncated: the file registers more handlers, or this one more
	// times, than are kept: Routes may lack some, or be absent though one
	// reaches the sink.
	RoutesTruncated bool `json:"routes_truncated,omitempty"`
}

// Engine holds compiled rules. It is safe for concurrent use.
type Engine struct {
	byLang map[string][]*crule
	// yieldLevel orders the second pass so that a rule comes before the rules
	// it yields to (yields.go): a rule no other rule yields to is at 0, one
	// that is yielded to is one past the rules yielding to it.
	yieldLevel map[string]int
	watch      map[string]bool // "m:" modules and "w:" names some rule's unless_imports looks for (imports.go)
	Limits     Limits
	// SourcePrefilter (on in New) skips the rules none of whose sources occur in
	// a file: a file scanned on its own gets input only from them, in the first
	// pass and in the second, where calls are followed inside the file. A scan
	// that brings input from elsewhere (other files, framework routes, as a
	// project mode will) must turn it off. Library mode never uses it.
	SourcePrefilter bool
	// Library turns on library mode: the parameters of public functions and
	// methods are treated as input, and a finding needs that input embedded in a
	// larger string (a query, a command, code), not passed through as is. It
	// applies to the libClasses only (a library building paths from its
	// parameters is normal), and not to test files. Set it only when the scanned
	// tree is itself a package or library whose callers are not part of the
	// scan; it is off for applications and for the server patrol.
	Library bool

	routes    map[string][]*croute // route models by language (routes.go)
	routeByID map[string]*croute
}

type crule struct {
	rule                   rules.Rule
	sources, sinks         []*pat // code patterns
	memberWild             bool   // a source ends in ->* ($request->*), which a Laravel project's untyped parameter reads (callbacks.go)
	textSources, textSinks []*pat // text inside string literals
	sanitizers             []*pat
	args                   map[*pat]*argCond
	argsMore               map[*pat][]*argCond // a sink's further [[args]] blocks: a finding when any one holds
	leading                bool                // some sink needs a fixed prefix, so values track raw input
	ctypes                 bool                // some args block has unless_content_type: record Content-Type statements (ctype.go)
	srcScope               map[*pat][]string   // sources of a route model that count on $this only in a class extending one of these (routes.go)
	srcThis                map[*pat]bool       // sources of a route model that count only on $this or $this->parent (this_only)
	output                 bool                // every sink writes to a page (has a context condition): see context.go
}

type argCond struct {
	arg            *int
	name           string // the argument's parameter name, when passed by name
	when, unless   []*pat
	whole, leading bool
	context        []uint8 // output contexts that count (ctxHTML ...); empty: any
	markup         bool    // context: only input after markup written in the same value (contextTaint)
	literal        bool
	key            string // the value under this key of an object argument (keyValue)
	keys           bool   // an array, object or dict literal argument counts by its keys (keysVal)
	minLen         int    // literal: the shortest string that counts
	exclude        []*regexp.Regexp
	unlessAt       string   // where unless looks: "" anywhere, "start", "top" (rules.Args.UnlessAt)
	receiver       []*pat   // a method sink counts only on a receiver these name (receiver.go)
	notReceiver    []*pat   // nor on an object surely of one of these classes (receiver.go)
	unlessCT       []string // nor once the response's Content-Type is one of these on every path (ctype.go)
	unlessImports  []string // nor in a file importing one of these modules (imports.go)
	importsNot     []string // ... unless the file or the receiver names one of these
	unlessSub      []*pat   // the argument does not count when it is one item of one of these (request.files["f"])
	unlessAfter    []*pat   // text patterns: nor when all the input in it comes after one of these (unlessafter.go)
}

// New compiles rules. A pattern that does not lex as code of its language is an error.
func New(rs []rules.Rule) (*Engine, error) {
	e := &Engine{byLang: map[string][]*crule{}, Limits: DefaultLimits, SourcePrefilter: true, routes: map[string][]*croute{}, routeByID: map[string]*croute{}}
	for _, r := range rs {
		c, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.ID, err)
		}
		e.byLang[r.Lang] = append(e.byLang[r.Lang], c)
		for _, ac := range c.args {
			for _, m := range ac.unlessImports {
				e.watchFor("m:" + m)
			}
			for _, w := range ac.importsNot {
				e.watchFor("m:" + w)
				e.watchFor("w:" + w)
			}
		}
	}
	routes, err := rules.LoadRoutes()
	if err == nil {
		err = e.compileRoutes(routes)
	}
	if err != nil {
		return nil, fmt.Errorf("route models: %w", err)
	}
	byID := map[string]*crule{}
	for _, cs := range e.byLang {
		for _, c := range cs {
			byID[c.rule.ID] = c
		}
	}
	e.yieldLevel = map[string]int{}
	var level func(id string, depth int) int
	level = func(id string, depth int) int {
		if v, ok := e.yieldLevel[id]; ok || depth > len(byID) {
			return v
		}
		v := 0
		for _, c := range byID {
			if slices.Contains(c.rule.YieldsTo, id) {
				v = max(v, level(c.rule.ID, depth+1)+1)
			}
		}
		e.yieldLevel[id] = v
		return v
	}
	for id := range byID {
		level(id, 0)
	}
	return e, nil
}

// foldMembers marks the method and class names of PHP sink and sanitizer
// patterns to match in any case, as PHP calls them: the last name after ->
// or :: ($wpdb->query matches $wpdb->Query(...), DB::raw DB::RAW(...)) and
// the class before :: (db::raw). A name followed by "(" is folded already
// (compilePattern). A name with -> after it is a property ($this->db in
// $this->db->escape(), which PHP reads by case: $this->DB is another), so
// it keeps its case; so do variables ($WPDB is not $wpdb) and sources,
// whose members may be properties.
func foldMembers(ps []*pat) {
	for _, p := range ps {
		if !p.php {
			continue
		}
		for k, t := range p.toks {
			if t.Kind != Ident {
				continue
			}
			next := Token{}
			if k+1 < len(p.toks) {
				next = p.toks[k+1]
			}
			if next.op("->") || next.op("?->") {
				continue // a property on the way: by case
			}
			if k > 0 && memberOp(true, p.toks[k-1]) || next.op("::") {
				p.toks[k].Flags |= FlagFold
			}
		}
	}
}

func compileRule(r rules.Rule) (*crule, error) {
	c := &crule{rule: r, args: map[*pat]*argCond{}}
	text := map[string]bool{}
	for _, t := range r.Text {
		text[t] = true
	}
	compile := func(list []string, code, txt *[]*pat) (map[string]*pat, error) {
		byRaw := map[string]*pat{}
		for _, raw := range list {
			p, err := compilePattern(r.Lang, raw, text[raw])
			if err != nil {
				return nil, err
			}
			byRaw[raw] = p
			if p.text != nil {
				*txt = append(*txt, p)
			} else {
				*code = append(*code, p)
			}
		}
		return byRaw, nil
	}
	srcs, err := compile(r.Sources, &c.sources, &c.textSources)
	if err != nil {
		return nil, err
	}
	for _, sp := range c.sources {
		c.memberWild = c.memberWild || sp.memberWild
	}
	for _, sa := range r.SourceArgs {
		if sa.Arg < 1 || len(sa.Values) == 0 || len(sa.Sources) == 0 {
			return nil, fmt.Errorf("source_args: needs sources, arg (from 1) and values")
		}
		for _, s := range sa.Sources {
			p, ok := srcs[s]
			if !ok || p.text != nil || p.argOpen() < 0 || p.callParen() < 0 && sa.Arg != 1 {
				return nil, fmt.Errorf("source_args: %q is not one of the call or index sources (an index source takes arg 1)", s)
			}
			p.srcArg, p.srcVals = sa.Arg, map[string]bool{}
			for _, v := range sa.Values {
				p.srcVals[strings.ToLower(v)] = true
			}
		}
	}
	c.setNotMembers()
	sinks, err := compile(r.Sinks, &c.sinks, &c.textSinks)
	if err != nil {
		return nil, err
	}
	var none []*pat
	if _, err := compile(r.Sanitizers, &c.sanitizers, &none); err != nil {
		return nil, err
	}
	for _, sp := range c.sanitizers {
		if sp.php && len(sp.toks) == 1 && sp.toks[0].Kind == Ident {
			sp.toks[0].Flags |= FlagFold // a sanitizer named alone is a function: EscapeShellArg($x) cleans
		}
	}
	foldMembers(c.sinks)
	foldMembers(c.sanitizers)
	for _, a := range r.Args {
		ac := &argCond{arg: a.Arg, name: a.Name, whole: a.Whole, leading: a.Leading, literal: a.Literal, key: a.Key, keys: a.Keys, minLen: a.MinLen, unlessAt: a.UnlessAt,
			unlessImports: a.UnlessImports, importsNot: a.UnlessImportsNot, markup: a.Markup}
		switch {
		case a.UnlessAt != "" && a.UnlessAt != "start" && a.UnlessAt != "top":
			return nil, fmt.Errorf("args: unless_at %q is not start or top", a.UnlessAt)
		case a.UnlessAt != "" && len(a.Unless) == 0:
			return nil, fmt.Errorf("args: unless_at needs unless")
		case len(a.UnlessImportsNot) > 0 && len(a.UnlessImports) == 0:
			return nil, fmt.Errorf("args: unless_imports_not needs unless_imports")
		case a.Markup && len(a.Context) == 0:
			return nil, fmt.Errorf("args: markup needs context")
		}
		for _, ct := range a.UnlessContentType {
			ac.unlessCT = append(ac.unlessCT, strings.ToLower(ct))
			c.ctypes = true
		}
		if (a.MinLen != 0 || len(a.Exclude) > 0) && !a.Literal {
			return nil, fmt.Errorf("args: min_len and exclude need literal")
		}
		for _, x := range a.Exclude {
			re, err := regexp.Compile("(?i)" + x)
			if err != nil {
				return nil, fmt.Errorf("args: exclude %q: %w", x, err)
			}
			ac.exclude = append(ac.exclude, re)
		}
		for _, name := range a.Context {
			cs, ok := contextNames[name]
			if !ok {
				return nil, fmt.Errorf("args: unknown context %q", name)
			}
			ac.context = append(ac.context, cs...)
		}
		c.leading = c.leading || a.Leading
		for _, raw := range a.UnlessAfter {
			p, err := compilePattern(r.Lang, raw, true)
			if err != nil {
				return nil, err
			}
			ac.unlessAfter = append(ac.unlessAfter, p)
		}
		for _, list := range []struct {
			raw []string
			out *[]*pat
		}{{a.When, &ac.when}, {a.Unless, &ac.unless}, {a.Receiver, &ac.receiver}, {a.NotReceiver, &ac.notReceiver}, {a.UnlessSubscript, &ac.unlessSub}} {
			for _, raw := range list.raw {
				p, err := compilePattern(r.Lang, raw, false)
				if err != nil {
					return nil, err
				}
				*list.out = append(*list.out, p)
			}
		}
		targets := a.Sinks
		if len(targets) == 0 {
			targets = r.Sinks
		}
		for _, s := range targets {
			p, ok := sinks[s]
			if !ok {
				return nil, fmt.Errorf("args: %q is not one of the sinks", s)
			}
			if c.args[p] != nil {
				if c.argsMore == nil {
					c.argsMore = map[*pat][]*argCond{}
				}
				c.argsMore[p] = append(c.argsMore[p], ac)
				continue
			}
			c.args[p] = ac
		}
	}
	all := slices.Collect(maps.Values(c.args))
	for _, more := range c.argsMore {
		all = append(all, more...)
	}
	for _, ac := range all {
		for _, x := range ac.context {
			if x == ctxURL {
				c.leading = true // track fixed prefixes: a value that starts with one cannot pick a scheme
			}
		}
	}
	c.chainSinks()
	c.output = len(c.sinks) > 0 && len(c.textSinks) == 0
	for _, s := range c.sinks {
		if ac := c.args[s]; ac == nil || len(ac.context) == 0 {
			c.output = false
		}
	}
	return c, nil
}

// LangOf returns the language of a file name ("php", "python", "js", or the
// dialects "jsx", "ts" and "tsx", which use the JavaScript rules), or "".
func LangOf(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".php", ".phtml", ".php5", ".inc":
		return "php"
	case ".py":
		return "python"
	case ".js", ".mjs", ".cjs":
		return "js"
	case ".jsx":
		return "jsx"
	case ".ts", ".mts", ".cts":
		return "ts"
	case ".tsx":
		return "tsx"
	}
	return ""
}

// Scan applies the rules of lang to one file. When the file hits the Limits it
// returns what was found so far and ErrLimit. Every line is read; when a
// minified or bundled JavaScript file stops early, ErrMinified is joined to the
// reason, so the audit can tell generated code from hand-written code.
func (e *Engine) Scan(lang, path string, src []byte) ([]Finding, error) {
	out, _, err := e.scan(lang, path, src, nil, false, false)
	if err != nil && baseLang(lang) == "js" && Minified(src) {
		err = errors.Join(ErrMinified, err)
	}
	return out, err
}

// ScanTimed is Scan, and also tells whether a time limit cut the scan short:
// such a result depends on how busy the machine was, so it is not one to keep
// for a later audit.
func (e *Engine) ScanTimed(lang, path string, src []byte) ([]Finding, bool, error) {
	out, timed, err := e.scan(lang, path, src, nil, false, false)
	if err != nil && baseLang(lang) == "js" && Minified(src) {
		err = errors.Join(ErrMinified, err)
	}
	return out, timed, err
}

// Scan applies the rules to one file of the project, following its calls into
// the project's other files. A finding can name another file: the line in the
// callee a tainted argument reaches. Each finding is returned once per project.
func (p *Project) Scan(path string, src []byte) ([]Finding, error) {
	out, _, err := p.e.scan(LangOf(path), path, src, p, false, true)
	return out, err
}

// ScanCalls is Scan without the analysis of each function on its own: only
// what following calls finds, for a file already scanned with Engine.Scan. It
// returns ErrCalls when following calls was cut short.
func (p *Project) ScanCalls(path string, src []byte) ([]Finding, error) {
	out, _, err := p.e.scan(LangOf(path), path, src, p, true, true)
	return out, err
}

// ScanCallsTimed is ScanCalls for a result kept from one audit to the next:
// every finding of the file is returned, also those another file's scan
// returned already, and timed tells whether the clock, or another of the
// project's caps that depend on the machine (heap), cut it short, or the
// project's work cap, which a later audit goes on past. See also Unsteady.
func (p *Project) ScanCallsTimed(path string, src []byte) ([]Finding, bool, error) {
	return p.e.scan(LangOf(path), path, src, p, true, false)
}

// CallsPart is what ScanCallsPart did with one file.
type CallsPart struct {
	Found []Finding // the findings of the rules in Done
	Done  []string  // the rules whose calls were followed to their end
	At    string    // the rule the clock cut short ("" when it did not)
	Cut   bool      // a cap cut one of Done short (as ErrCalls)
	Timed bool      // the clock, the heap or the project's work cap cut the scan short (as ScanCallsTimed)
	// FileTime: only the file's own time limit (Limits.MaxTime) cut it short,
	// not the project's clock or heap: other files can still be followed.
	FileTime bool
}

// ScanCallsPart is ScanCallsTimed that leaves out the rules in skip, whose
// calls were followed in an earlier audit, and tells which rules it followed
// to their end: their findings are what it returns, also when the clock cut
// the scan short, so a file too slow for one audit is done a few rules at a
// time.
func (p *Project) ScanCallsPart(path string, src []byte, skip map[string]bool) (CallsPart, error) {
	p.skip, p.part, p.partCut, p.partAt = skip, nil, false, ""
	defer func() { p.skip, p.part = nil, nil }()
	found, timed, err := p.e.scan(LangOf(path), path, src, p, true, false)
	fileTime := timed && p.stopped == "" && time.Now().Before(p.deadline)
	return CallsPart{Found: found, Done: p.part, At: p.partAt, Cut: p.partCut, Timed: timed, FileTime: fileTime}, err
}

// scan is Scan in all its forms; dedup leaves out what the project returned
// already, and timed tells whether a clock or the project's heap cap cut it short.
func (e *Engine) scan(lang, path string, src []byte, proj *Project, callsOnly, dedup bool) (_ []Finding, timed bool, _ error) {
	base := baseLang(lang)
	rs := e.byLang[base]
	if len(rs) == 0 {
		return nil, false, nil
	}
	if proj != nil {
		proj.unsteady = false
		proj.scanning = path
		defer func() { proj.scanning = "" }()
		// The project's work cap, checked before each file: where calls stop
		// crossing files depends on the files and their order, not on time. It
		// is passed by at most one file's calls pass, itself capped per rule
		// (MaxCallWork); what work does not count (relevance, the call graph)
		// is bounded by the project's safety clock, an audit's time left.
		if proj.stopped == "" && proj.work >= proj.opt.MaxWork {
			proj.stop("following calls across files reached the project's work cap", CutProjectWork)
		}
	}
	b := newBudget(e.Limits)
	toks := lex(lang, string(src), b)
	if b.hit {
		return nil, b.timeHit, cutErr(ErrLimit, b.cut())
	}
	tree := parse(base, toks, b)
	ff := newFileFuncs(collectFuncs(tree, base), base)
	routeFns := e.handlers(base, toks, tree, ff) // functions a framework calls with request data (routes.go)
	local := len(routeFns)
	routeFns = e.projectHandlers(proj, path, ff, routeFns) // ... registered in another file (urls.py, routes/web.php)
	viaProject := len(routeFns) > local
	mws := koaMiddleware(base, toks, tree, ff, proj) // Koa's app.use(fn): fn's context is followed as a handler's (reqalias.go)
	defs := phpDefines(base, toks)
	if proj != nil {
		proj.keep(path, &fileCtx{lang: base, tree: tree, ff: ff, tokens: len(toks), rdefs: fileRecvDefs(base, toks), rcls: fileRecvClasses(base, toks), ifacts: e.importFacts(base, toks), defs: defs})
	}
	var out []Finding
	add := func(r *crule, lines ...[]loc) {
		seen := map[loc]bool{}
		for _, ls := range lines {
			for _, l := range ls {
				if seen[l] {
					continue
				}
				seen[l] = true
				if dedup && proj != nil {
					k := r.rule.ID + "\x00" + l.path + "\x00" + strconv.Itoa(l.line)
					if proj.seen[k] {
						continue
					}
					proj.seen[k] = true
				}
				out = append(out, Finding{RuleID: r.rule.ID, Path: l.path, Line: l.line, Severity: r.rule.Severity,
					Title: r.rule.Title, CWE: r.rule.CWE, Fix: r.rule.Fix, Tier: r.rule.Tier})
			}
		}
	}
	// First every rule inside each function, as without summaries: what is
	// written out in the file is reported whatever the calls cost. In a project
	// a file without a sink may still pass its input to another file's sink.
	var ruleList []*crule
	direct := map[*crule][]loc{}
	spans := map[string]map[loc][]string{} // rule id: the sink calls each line was reported through (yields.go)
	spansOf := func(r *crule) map[loc][]string {
		if spans[r.rule.ID] == nil {
			spans[r.rule.ID] = map[loc][]string{}
		}
		return spans[r.rule.ID]
	}
	names := nameSet(toks, map[string]bool{})
	nextHdrs := base == "js" && importsModule(toks, "next/headers") // h = await headers(): h.get( is a source no text shows (reqalias.go)
	si := newSrcIndex(toks, b)
	var strs map[string]bool
	for _, r := range rs {
		if time.Now().After(b.deadline) { // cheap: once per rule
			b.hit, b.timeHit = true, true
			break
		}
		hs := si.names(r.sinks, r.textSinks, names, src) && si.hasSink(r)
		if !hs && r.rule.Lang == "php" {
			hs = namedSink(r, strNames(toks, &strs)) // array_map('system', $x): a builtin sink given by name (callbacks.go)
		}
		if !hs && proj != nil && !proj.sinkRules[r.rule.ID] {
			continue // no file of the project holds a sink of it: nothing to reach across files either
		}
		// In a project a file without a sink may pass input, its own or a route
		// handler's parameters, to another file's sink; on its own it has nothing
		// to find.
		if !hs && (proj == nil || len(routeFns) == 0 && (len(r.sources) == 0 && len(r.textSources) == 0 || !si.hasSource(r))) {
			continue
		}
		// No source of it in the file: nothing to find, in either pass. Only for
		// a file on its own without route handlers or Koa middleware: in a project
		// input also comes from the other files, and a handler's parameters (a
		// middleware's context, through an alias) are input with no source name
		// in the file.
		if proj == nil && len(routeFns) == 0 && len(mws) == 0 && e.skipBySources(r, names, src, si) && !(nextHdrs && readsNextHeaders(r)) {
			continue
		}
		ruleList = append(ruleList, r)
		if hs && !callsOnly {
			a := &analysis{r: r, php: base == "php", py: base == "python", js: base == "js", b: b, kw: keywords[base], seen: map[loc]bool{}, defs: defs, file: path, ftoks: toks, routes: routeFns, mws: mws, cproj: proj,
				sinkSpans: spansOf(r)}
			a.block(tree, state{})
			direct[r] = a.lines
		}
		if b.hit {
			break
		}
	}
	// Then again with calls followed, on a token budget of its own and the time
	// left of the same MaxTime. A rule that finishes with every summary complete
	// takes this result (summaries also clear what a sanitizing helper returns);
	// one cut short, or with a summary that hit a cap and may say too little,
	// keeps its first result as well.
	limited := b.hit || b.limited || time.Now().After(b.deadline) // the first pass did not finish
	timed = b.timeHit || time.Now().After(b.deadline)
	callsCut := false
	var cut Cut // what cut the scan short (cut.go)
	if limited {
		cut = b.cut()
		if time.Now().After(b.deadline) {
			cut |= CutClock
		}
	}
	finished := map[*crule]bool{}
	if !b.hit && (len(ff.byKey) > 0 || proj != nil) {
		b2 := newBudget(e.Limits)
		b2.workCut = CutCallWork
		b2.deadline = b.deadline // one file stays within MaxTime in all
		if proj != nil {
			// Across files the project's clock applies (an audit's time left):
			// more rules must not mean less followed per rule.
			b2.deadline = proj.deadline
		}
		perRule := e.Limits.MaxCallWork
		if perRule <= 0 {
			perRule = DefaultLimits.MaxCallWork
		}
		// a rule run here makes the rules it yields to run here too, whether a
		// call can change them or not: yields_to looks at what the same scan
		// found (yields.go), so a rule this pass leaves out would not take the
		// call back. They run after it (yieldLevel); their own result is what the
		// first pass found when no call changes it.
		order := slices.Clone(ruleList)
		slices.SortStableFunc(order, func(x, y *crule) int { return e.yieldLevel[x.rule.ID] - e.yieldLevel[y.rule.ID] })
		forced := map[string]bool{}
		for _, r := range order {
			if proj != nil && proj.skip[r.rule.ID] {
				continue // followed in an earlier audit (ScanCallsPart)
			}
			ruleDone := func() {
				// Once the project stopped (its clock, its heap), calls no longer
				// cross files and resolve to nothing without a word: a rule
				// finished then followed none of them and is not done.
				if proj != nil && proj.stopped == "" {
					proj.part = append(proj.part, r.rule.ID)
					proj.partCut = proj.partCut || callsCut || b2.limited
				}
			}
			b2.maxWork = b2.work + perRule // each rule's own work cap
			b2.sumWork = perRule           // and each summary its own (interproc.go, own)
			sc := newSummaries(ff)
			if proj != nil {
				if sc == nil {
					sc = &summaries{ff: ff, funcs: ff.byKey, done: map[string]*summary{}, busy: map[string]bool{}, rel: map[string]uint8{}, srcRel: map[string]uint8{}, retUnk: map[string]uint8{}, keyed: map[string]*summary{}}
				}
				// Summaries are worked out the same whoever asks (own): those the
				// project has of this file already (as another file's callee, or a
				// cycle settled through it) are the ones this scan would work out.
				key := ruleFile{r.rule.ID, path}
				if old := proj.sums[key]; old != nil {
					sc.done, sc.rel, sc.direct, sc.cross, sc.keyed, sc.srcMay, sc.srcRel, sc.retUnk = old.done, old.rel, old.direct, old.cross, old.keyed, old.srcMay, old.srcRel, old.retUnk
				} else if kept := proj.kept[key]; kept != nil {
					kept.restore(sc)
					delete(proj.kept, key)
				}
				proj.sums[key] = sc
			}
			a := &analysis{r: r, php: base == "php", py: base == "python", js: base == "js", b: b2, kw: keywords[base], seen: map[loc]bool{}, sc: sc,
				defs: defs, file: path, proj: proj, ftoks: toks, routes: routeFns, mws: mws, sinkSpans: spansOf(r)}
			if !e.Library && !a.r.output && !viaProject && !forced[r.rule.ID] && !a.crossNeeded(tree) && !(proj != nil && proj.laravel && a.php && r.memberWild) {
				// no call can change this rule's result: the first pass stands. Output
				// rules read calls to the file's own functions in this pass only
				// (htmlctx.go); handlers registered in another file need it too. In a
				// Laravel project a PHP rule reading $request->* is run here too (the
				// first pass, without the project, does not know an untyped $request
				// is Laravel's: callbacks.go laravelRequest); and so is a rule
				// another rule run here yields to (forced).
				ruleDone()
				continue
			}
			for _, to := range r.rule.YieldsTo {
				forced[to] = true
			}
			a.block(tree, state{})
			if e.Library && libClasses[r.rule.Class] && !testPath(path) && !b2.hit {
				l := &analysis{r: r, php: a.php, py: a.py, js: a.js, b: b2, kw: a.kw, seen: a.seen, sc: sc, lib: true, defs: defs, file: path, proj: proj, ftoks: toks, routes: routeFns, mws: mws,
					sinkSpans: a.sinkSpans}
				l.block(tree, state{})
				a.lines = append(a.lines, l.lines...)
			}
			if proj != nil && proj.byMachine {
				// The project stopped during the rule (its clock, its heap): calls
				// stopped crossing files part way, as with the scan's own clock.
				callsCut, timed = true, true
				cut |= proj.stopCut
				add(r, direct[r])
				delete(direct, r)
				break
			}
			if b2.hit {
				callsCut = true
				cut |= callsCutOf(b2, proj)
				if b2.timeHit {
					// Cut short by the clock, the flows found so far are not kept: how
					// far it got depends on the machine's load, and a summary it had no
					// time for may be the check that clears a flow.
					add(r, direct[r])
					delete(direct, r)
					if proj != nil {
						proj.partAt = r.rule.ID
					}
					break
				}
				// Cut short by its work cap, the flows found so far are kept (the
				// cap falls at the same place every time), and the next rule starts
				// with a cap of its own.
				add(r, direct[r], a.lines)
				delete(direct, r)
				b2.hit = false
				ruleDone()
				continue
			}
			if sc.capped {
				add(r, direct[r], a.lines)
				delete(direct, r)
				callsCut = true
				cut |= CutSummary
				ruleDone()
				continue
			}
			add(r, a.lines)
			finished[r] = true
			ruleDone()
		}
		callsCut = callsCut || b2.hit || b2.limited
		if b2.hit || b2.limited {
			cut |= callsCutOf(b2, proj)
		}
		timed = timed || b2.timeHit
		if proj != nil {
			proj.work += b2.work
		}
	}
	// Past a project cap calls no longer cross files: say so, not "clean".
	if proj != nil && proj.stopped != "" {
		callsCut = true
		cut |= proj.stopCut
		// The clock or the heap, or the work cap a later audit goes on past;
		// not the file limit.
		timed = timed || proj.byMachine || proj.stopCut&CutProjectWork != 0
	}
	for _, r := range ruleList {
		if lines, ok := direct[r]; ok && !finished[r] {
			add(r, lines)
		}
	}
	byID := map[string]*crule{}
	for _, r := range rs {
		byID[r.rule.ID] = r
	}
	out = yieldFindings(out, byID, spans)             // one sink two rules report: the one it yields to (yields.go)
	e.annotateRoutes(out, base, path, toks, tree, ff) // which routes reach each sink's handler; no finding changes
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].RuleID < out[j].RuleID
	})
	switch {
	case limited:
		return out, timed, cutErr(ErrLimit, cut)
	case b.partial:
		return out, timed, ErrPartial
	case callsCut:
		return out, timed, cutErr(ErrCalls, cut)
	}
	return out, timed, nil
}

// hasSink reports whether one of the rule's sinks occurs in the file at all,
// matched as the analysis matches sinks (strictly): exec( is not re.exec(, but
// is child_process.exec( once the module is normalised (FlagModule).
func hasSink(r *crule, toks []Token) bool {
	for i := range toks {
		for _, s := range r.sinks {
			if s.text == nil && s.at(toks, i, true) {
				return true
			}
		}
		if toks[i].Kind == Str {
			for _, s := range r.textSinks {
				if s.text.MatchString(toks[i].Text) {
					return true
				}
			}
		}
		if toks[i].Kind == Str && len(toks[i].Parts) > 0 && partsHaveSink(r, toks[i].Parts) {
			return true
		}
	}
	return false
}

func partsHaveSink(r *crule, parts []Part) bool {
	for _, p := range parts {
		if hasSink(r, p.Toks) {
			return true
		}
	}
	return false
}

// libClasses are the rule classes library mode applies to: input embedded in
// SQL, a shell command or code is the library's own doing.
var libClasses = map[string]bool{"sqli": true, "cmdi": true, "code-eval": true}

// testPath reports whether a file is test code: tests/ or test/ directories,
// test_x.py, x_test.py, x.test.js, x.spec.js.
func testPath(path string) bool {
	p := "/" + filepath.ToSlash(path)
	base := filepath.Base(p)
	return strings.Contains(p, "/tests/") || strings.Contains(p, "/test/") || strings.Contains(p, "/__tests__/") ||
		strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") || strings.HasSuffix(base, "Test.php") ||
		strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}

// ScanFile is Scan with the language taken from the file name.
func (e *Engine) ScanFile(path string, src []byte) ([]Finding, error) {
	return e.Scan(LangOf(path), path, src)
}

func lex(lang, src string, b *budget) []Token {
	switch lang {
	case "php":
		return lexPHP(src, b, false)
	case "python":
		return lexPython(src, b)
	case "js":
		return lexJS(src, b)
	case "jsx":
		return lexJSX(src, b, true)
	case "ts", "tsx":
		return lexTS(src, b, lang == "tsx")
	}
	return nil
}

// skipBySources reports whether the first pass leaves out rule r for a file
// with these names (see SourcePrefilter).
func (e *Engine) skipBySources(r *crule, names map[string]bool, src []byte, si *srcIndex) bool {
	noSources := len(r.sources) == 0 && len(r.textSources) == 0 // sourceNames, with the index
	return e.SourcePrefilter && !e.Library && (!noSources && !si.names(r.sources, r.textSources, names, src) || !si.hasSource(r))
}

// srcIndex finds the rules' sources and sinks in one file without reading the
// file once per rule: where each token is, inside string interpolations too,
// is listed once (on the first search), a pattern is tried only where its
// first token is, and what was found for a pattern holds for every rule
// listing it. The cost stays the file's tokens and the places tried, whatever
// the number of rules.
type srcIndex struct {
	toks  []Token             // until the first search
	lists [][]Token           // the file's tokens, then each interpolation's
	at    map[tokKey][]srcPos // where each token other than a string literal is
	strs  []srcPos            // where each string literal is
	found map[string]bool     // per pattern, whether it occurs
	b     *budget             // the file's: its clock bounds the search
	tries int
}

type tokKey struct {
	kind Kind
	text string
}

type srcPos struct{ list, i int32 }

// newSrcIndex is the index of toks; b may be nil (no clock).
func newSrcIndex(toks []Token, b *budget) *srcIndex {
	return &srcIndex{toks: toks, found: map[string]bool{}, b: b}
}

// build lists where the tokens are.
func (si *srcIndex) build() {
	si.at = map[tokKey][]srcPos{}
	var add func(toks []Token)
	add = func(toks []Token) {
		l := int32(len(si.lists))
		si.lists = append(si.lists, toks)
		for i, t := range toks {
			if t.Kind == Str {
				si.strs = append(si.strs, srcPos{l, int32(i)})
				for _, p := range t.Parts {
					add(p.Toks)
				}
				continue
			}
			k := tokKey{t.Kind, t.Text}
			si.at[k] = append(si.at[k], srcPos{l, int32(i)})
			if low := strings.ToLower(t.Text); t.Kind == Ident && low != t.Text {
				k = tokKey{Ident, low} // where a case-folded pattern name looks (FlagFold)
				si.at[k] = append(si.at[k], srcPos{l, int32(i)})
			}
		}
	}
	add(si.toks)
	si.toks = nil
}

// hasSource reports whether one of the rule's sources occurs in the file, matched
// token by token as the analysis matches sources: the names of request.url both
// being in a large bundle is not request.url. Out of time it says yes, and the
// file's scan stops on its clock.
func (si *srcIndex) hasSource(r *crule) bool {
	if len(r.sources) == 0 && len(r.textSources) == 0 {
		return true
	}
	for _, s := range r.sources {
		if s.text == nil && si.has("c"+s.raw, s, false) {
			return true
		}
	}
	for _, s := range r.textSources {
		if si.has("t"+s.text.String(), s, false) {
			return true
		}
	}
	return false
}

// hasSink reports whether one of the rule's sinks occurs in the file at all,
// matched as the analysis matches sinks (strictly, see the function hasSink).
func (si *srcIndex) hasSink(r *crule) bool {
	for _, s := range r.sinks {
		if s.text == nil && si.has("s"+s.raw+"\x00"+s.chainKey(), s, true) {
			return true
		}
	}
	for _, s := range r.textSinks {
		if si.has("t"+s.text.String(), s, true) { // in string literals, as a text source
			return true
		}
	}
	return false
}

// names is anyName with each text pattern matched against src once per file.
func (si *srcIndex) names(code, text []*pat, names map[string]bool, src []byte) bool {
	return anyName(code, text, names, func(p *pat) bool {
		key := "m" + p.text.String()
		f, ok := si.found[key]
		if !ok {
			f = p.text.Match(src)
			si.found[key] = f
		}
		return f
	})
}

// has reports whether pattern s occurs, looking it up once per file under key.
func (si *srcIndex) has(key string, s *pat, strict bool) bool {
	if f, ok := si.found[key]; ok {
		return f
	}
	if si.at == nil {
		si.build()
	}
	f := si.search(s, strict)
	if !si.b.hitLimit() {
		si.found[key] = f
	}
	return f
}

func (si *srcIndex) search(s *pat, strict bool) bool {
	try := func(ps []srcPos, ok func(toks []Token, i int) bool) bool {
		for _, p := range ps {
			if si.tries++; si.tries&1023 == 0 && si.b != nil && time.Now().After(si.b.deadline) {
				si.b.hit, si.b.timeHit = true, true
				return true
			}
			if ok(si.lists[p.list], int(p.i)) {
				return true
			}
		}
		return false
	}
	if s.text != nil {
		return try(si.strs, func(toks []Token, i int) bool { return s.text.MatchString(toks[i].Text) })
	}
	at := func(toks []Token, i int) bool { return s.at(toks, i, false) || s.baseAt(toks, i) } // a source
	if strict {
		at = func(toks []Token, i int) bool { return s.at(toks, i, true) } // a sink
	}
	if first := s.toks[0]; first.Kind != Str {
		if first.Flags&FlagFold != 0 {
			return try(si.at[tokKey{Ident, strings.ToLower(first.Text)}], at)
		}
		return try(si.at[tokKey{first.Kind, first.Text}], at)
	}
	return try(si.strs, at) // a string literal matches by more than its text (tokEq)
}
