// Package engine applies Shentu's code rules (package rules) to PHP, Python and
// JavaScript files. It lexes the file by hand, splits it into statements and
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
	"sort"
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
	when, unless   []*pat
	whole, leading bool
	context        []uint8 // output contexts that count (ctxHTML ...); empty: any
	literal        bool
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
	if _, err := compile(r.Sources, &c.sources, &c.textSources); err != nil {
		return nil, err
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
		ac := &argCond{arg: a.Arg, whole: a.Whole, leading: a.Leading, literal: a.Literal}
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
		}{{a.When, &ac.when}, {a.Unless, &ac.unless}} {
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
	c.output = len(c.sinks) > 0 && len(c.textSinks) == 0
	for _, s := range c.sinks {
		if ac := c.args[s]; ac == nil || len(ac.context) == 0 {
			c.output = false
		}
	}
	return c, nil
}

// LangOf returns the rule language for a file name ("php", "python", "js"), or "".
func LangOf(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".php", ".phtml", ".php5", ".inc":
		return "php"
	case ".py":
		return "python"
	case ".js", ".mjs", ".cjs", ".jsx":
		return "js"
	}
	return ""
}

// Scan applies the rules of lang to one file. When the file hits the Limits it
// returns what was found so far and ErrLimit. Every line is read; when a
// minified or bundled JavaScript file stops early, ErrMinified is joined to the
// reason, so the audit can tell generated code from hand-written code.
func (e *Engine) Scan(lang, path string, src []byte) ([]Finding, error) {
	out, err := e.scan(lang, path, src)
	if err != nil && lang == "js" && Minified(src) {
		err = errors.Join(ErrMinified, err)
	}
	return out, err
}

func (e *Engine) scan(lang, path string, src []byte) ([]Finding, error) {
	rs := e.byLang[lang]
	if len(rs) == 0 {
		return nil, nil
	}
	b := newBudget(e.Limits)
	toks := lex(lang, string(src), b)
	if b.hit {
		return nil, ErrLimit
	}
	tree := parse(lang, toks, b)
	ff := newFileFuncs(collectFuncs(tree, lang), lang)
	var out []Finding
	add := func(r *crule, lines ...[]int) {
		seen := map[int]bool{}
		for _, ls := range lines {
			for _, line := range ls {
				if seen[line] {
					continue
				}
				seen[line] = true
				out = append(out, Finding{RuleID: r.rule.ID, Path: path, Line: line, Severity: r.rule.Severity,
					Title: r.rule.Title, CWE: r.rule.CWE, Fix: r.rule.Fix, Tier: r.rule.Tier})
			}
		}
	}
	// First every rule inside each function, as without summaries: what is
	// written out in the file is reported whatever the calls cost.
	var ruleList []*crule
	direct := map[*crule][]int{}
	defs := phpDefines(lang, toks)
	names := nameSet(toks, map[string]bool{})
	for _, r := range rs {
		if !sinkNames(r, names, src) || !hasSink(r, toks) {
			continue // nothing in the file can be this rule's sink
		}
		if e.skipBySources(r, names, src) {
			continue // no source of it in the file: nothing to find, in either pass
		}
		ruleList = append(ruleList, r)
		a := &analysis{r: r, php: lang == "php", py: lang == "python", js: lang == "js", b: b, kw: keywords[lang], seen: map[int]bool{}, defs: defs}
		a.block(tree, state{})
		direct[r] = a.lines
		if b.hit {
			break
		}
	}
	// Then again with calls followed, on a budget of its own. A rule that
	// finishes takes this result (summaries also clear what a sanitizing helper
	// returns); one cut short keeps its first result too.
	limited := b.hit || b.limited
	finished := map[*crule]bool{}
	if !b.hit && len(ff.byKey) > 0 {
		b2 := newBudget(e.Limits)
		b2.deadline = b.deadline.Add(e.Limits.maxTime()) // a file takes at most twice MaxTime in all
		for _, r := range ruleList {
			sc := newSummaries(ff)
			a := &analysis{r: r, php: lang == "php", py: lang == "python", js: lang == "js", b: b2, kw: keywords[lang], seen: map[int]bool{}, sc: sc, defs: defs}
			a.block(tree, state{})
			if e.Library && libClasses[r.rule.Class] && !testPath(path) && !b2.hit {
				l := &analysis{r: r, php: a.php, py: a.py, js: a.js, b: b2, kw: a.kw, seen: a.seen, sc: sc, lib: true, defs: defs}
				l.block(tree, state{})
				a.lines = append(a.lines, l.lines...)
			}
			if b2.hit {
				add(r, direct[r], a.lines) // flows found before the budget ran out are real
				delete(direct, r)
				break
			}
			add(r, a.lines)
			finished[r] = true
		}
		limited = limited || b2.hit || b2.limited || time.Now().After(b2.deadline)
	}
	for _, r := range ruleList {
		if lines, ok := direct[r]; ok && !finished[r] {
			add(r, lines)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].RuleID < out[j].RuleID
	})
	switch {
	case limited || time.Now().After(b.deadline):
		return out, ErrLimit
	case b.partial:
		return out, ErrPartial
	}
	return out, nil
}

// hasSink reports whether one of the rule's sinks occurs in the file at all.
func hasSink(r *crule, toks []Token) bool {
	for i := range toks {
		for _, s := range r.sinks {
			if s.text == nil && s.at(toks, i, false) {
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
	}
	return nil
}

// skipBySources reports whether the first pass leaves out rule r for a file
// with these names (see SourcePrefilter).
func (e *Engine) skipBySources(r *crule, names map[string]bool, src []byte) bool {
	return e.SourcePrefilter && !e.Library && !sourceNames(r, names, src)
}
