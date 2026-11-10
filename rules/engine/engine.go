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
	"path/filepath"
	"regexp"
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
}

// Engine holds compiled rules. It is safe for concurrent use.
type Engine struct {
	byLang map[string][]*crule
	Limits Limits
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
}

type crule struct {
	rule                   rules.Rule
	sources, sinks         []*pat // code patterns
	textSources, textSinks []*pat // text inside string literals
	sanitizers             []*pat
	args                   map[*pat]*argCond
	leading                bool // some sink needs a fixed prefix, so values track raw input
	output                 bool // every sink writes to a page (has a context condition): see context.go
}

type argCond struct {
	arg            *int
	name           string // the argument's parameter name, when passed by name
	when, unless   []*pat
	whole, leading bool
	context        []uint8 // output contexts that count (ctxHTML ...); empty: any
	literal        bool
	key            string // the value under this key of an object argument (keyValue)
	keys           bool   // an array, object or dict literal argument counts by its keys (keysVal)
	minLen         int    // literal: the shortest string that counts
	exclude        []*regexp.Regexp
	receiver       []*pat // a method sink counts only on a receiver these name (receiver.go)
}

// New compiles rules. A pattern that does not lex as code of its language is an error.
func New(rs []rules.Rule) (*Engine, error) {
	e := &Engine{byLang: map[string][]*crule{}, Limits: DefaultLimits, SourcePrefilter: true}
	for _, r := range rs {
		c, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.ID, err)
		}
		e.byLang[r.Lang] = append(e.byLang[r.Lang], c)
	}
	return e, nil
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
	for _, sa := range r.SourceArgs {
		if sa.Arg < 1 || len(sa.Values) == 0 || len(sa.Sources) == 0 {
			return nil, fmt.Errorf("source_args: needs sources, arg (from 1) and values")
		}
		for _, s := range sa.Sources {
			p, ok := srcs[s]
			if !ok || p.text != nil || p.callParen() < 0 {
				return nil, fmt.Errorf("source_args: %q is not one of the call sources", s)
			}
			p.srcArg, p.srcVals = sa.Arg, map[string]bool{}
			for _, v := range sa.Values {
				p.srcVals[strings.ToLower(v)] = true
			}
		}
	}
	sinks, err := compile(r.Sinks, &c.sinks, &c.textSinks)
	if err != nil {
		return nil, err
	}
	var none []*pat
	if _, err := compile(r.Sanitizers, &c.sanitizers, &none); err != nil {
		return nil, err
	}
	for _, a := range r.Args {
		ac := &argCond{arg: a.Arg, name: a.Name, whole: a.Whole, leading: a.Leading, literal: a.Literal, key: a.Key, keys: a.Keys, minLen: a.MinLen}
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
		for _, list := range []struct {
			raw []string
			out *[]*pat
		}{{a.When, &ac.when}, {a.Unless, &ac.unless}, {a.Receiver, &ac.receiver}} {
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
			c.args[p] = ac
		}
	}
	for _, ac := range c.args {
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
// project's caps that depend on the machine (heap), cut it short. See also
// Unsteady.
func (p *Project) ScanCallsTimed(path string, src []byte) ([]Finding, bool, error) {
	return p.e.scan(LangOf(path), path, src, p, true, false)
}

// CallsPart is what ScanCallsPart did with one file.
type CallsPart struct {
	Found []Finding // the findings of the rules in Done
	Done  []string  // the rules whose calls were followed to their end
	At    string    // the rule the clock cut short ("" when it did not)
	Cut   bool      // a cap cut one of Done short (as ErrCalls)
	Timed bool      // the clock or the heap cut the scan short (as ScanCallsTimed)
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
	return CallsPart{Found: found, Done: p.part, At: p.partAt, Cut: p.partCut, Timed: timed}, err
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
	}
	b := newBudget(e.Limits)
	toks := lex(lang, string(src), b)
	if b.hit {
		return nil, b.timeHit, ErrLimit
	}
	tree := parse(base, toks, b)
	ff := newFileFuncs(collectFuncs(tree, base), base)
	if proj != nil {
		proj.keep(path, &fileCtx{lang: base, tree: tree, ff: ff, tokens: len(toks), rdefs: fileRecvDefs(base, toks)})
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
	defs := phpDefines(base, toks)
	names := nameSet(toks, map[string]bool{})
	for _, r := range rs {
		hs := sinkNames(r, names, src) && hasSink(r, toks)
		if !hs && (proj == nil || len(r.sources) == 0 && len(r.textSources) == 0 || !hasSource(r, toks)) {
			continue // nothing in the file can be this rule's sink; in a project, nor its source
		}
		if proj == nil && e.skipBySources(r, names, src, toks) {
			// no source of it in the file: nothing to find, in either pass. Never in
			// a project, where input also comes from the other files.
			continue
		}
		ruleList = append(ruleList, r)
		if hs && !callsOnly {
			a := &analysis{r: r, php: base == "php", py: base == "python", js: base == "js", b: b, kw: keywords[base], seen: map[loc]bool{}, defs: defs, file: path, ftoks: toks}
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
	finished := map[*crule]bool{}
	if !b.hit && (len(ff.byKey) > 0 || proj != nil) {
		b2 := newBudget(e.Limits)
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
		for _, r := range ruleList {
			if proj != nil && proj.skip[r.rule.ID] {
				continue // followed in an earlier audit (ScanCallsPart)
			}
			ruleDone := func() {
				if proj != nil {
					proj.part = append(proj.part, r.rule.ID)
					proj.partCut = proj.partCut || callsCut || b2.limited
				}
			}
			b2.maxWork = b2.work + perRule // each rule's own work cap
			sc := newSummaries(ff)
			if proj != nil {
				if sc == nil {
					sc = &summaries{ff: ff, funcs: ff.byKey, done: map[string]*summary{}, busy: map[string]bool{}, rel: map[string]uint8{}, retUnk: map[string]uint8{}}
				}
				proj.sums[r.rule.ID+"\x00"+path] = sc
			}
			a := &analysis{r: r, php: base == "php", py: base == "python", js: base == "js", b: b2, kw: keywords[base], seen: map[loc]bool{}, sc: sc,
				defs: defs, file: path, proj: proj, ftoks: toks}
			if !e.Library && !a.r.output && !a.crossNeeded(tree) {
				// no call can change this rule's result: the first pass stands. Output
				// rules read calls to the file's own functions in this pass only (htmlctx.go).
				ruleDone()
				continue
			}
			a.block(tree, state{})
			if e.Library && libClasses[r.rule.Class] && !testPath(path) && !b2.hit {
				l := &analysis{r: r, php: a.php, py: a.py, js: a.js, b: b2, kw: a.kw, seen: a.seen, sc: sc, lib: true, defs: defs, file: path, proj: proj, ftoks: toks}
				l.block(tree, state{})
				a.lines = append(a.lines, l.lines...)
			}
			if b2.hit {
				callsCut = true
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
				ruleDone()
				continue
			}
			add(r, a.lines)
			finished[r] = true
			ruleDone()
		}
		callsCut = callsCut || b2.hit || b2.limited
		timed = timed || b2.timeHit
	}
	// Past a project cap calls no longer cross files: say so, not "clean".
	if proj != nil && proj.stopped != "" {
		callsCut = true
		timed = timed || proj.byMachine // the clock or the heap, not the file limit
	}
	for _, r := range ruleList {
		if lines, ok := direct[r]; ok && !finished[r] {
			add(r, lines)
		}
	}
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
		return out, timed, ErrLimit
	case b.partial:
		return out, timed, ErrPartial
	case callsCut:
		return out, timed, ErrCalls
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
func (e *Engine) skipBySources(r *crule, names map[string]bool, src []byte, toks []Token) bool {
	return e.SourcePrefilter && !e.Library && (!sourceNames(r, names, src) || !hasSource(r, toks))
}

// hasSource reports whether one of the rule's sources occurs in the file, matched
// token by token as the analysis matches sources: the names of request.url both
// being in a large bundle is not request.url.
func hasSource(r *crule, toks []Token) bool {
	if len(r.sources) == 0 && len(r.textSources) == 0 {
		return true
	}
	for i := range toks {
		for _, s := range r.sources {
			if s.text == nil && (s.at(toks, i, false) || s.baseAt(toks, i)) {
				return true
			}
		}
		if toks[i].Kind == Str {
			for _, s := range r.textSources {
				if s.text.MatchString(toks[i].Text) {
					return true
				}
			}
			for _, p := range toks[i].Parts {
				if hasSource(r, p.Toks) {
					return true
				}
			}
		}
	}
	return false
}
