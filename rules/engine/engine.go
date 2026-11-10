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
	"fmt"
	"path/filepath"
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
}

type argCond struct {
	arg            *int
	name           string // the argument's parameter name, when passed by name
	when, unless   []*pat
	whole, leading bool
}

// New compiles rules. A pattern that does not lex as code of its language is an error.
func New(rs []rules.Rule) (*Engine, error) {
	e := &Engine{byLang: map[string][]*crule{}, Limits: DefaultLimits}
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
		ac := &argCond{arg: a.Arg, name: a.Name, whole: a.Whole, leading: a.Leading}
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
// returns what was found so far and ErrLimit.
func (e *Engine) Scan(lang, path string, src []byte) ([]Finding, error) {
	return e.scan(lang, path, src, nil, false)
}

// Scan applies the rules to one file of the project, following its calls into
// the project's other files. A finding can name another file: the line in the
// callee a tainted argument reaches. Each finding is returned once per project.
func (p *Project) Scan(path string, src []byte) ([]Finding, error) {
	return p.e.scan(LangOf(path), path, src, p, false)
}

// ScanCalls is Scan without the analysis of each function on its own: only
// what following calls finds, for a file already scanned with Engine.Scan. It
// returns ErrCalls when following calls was cut short.
func (p *Project) ScanCalls(path string, src []byte) ([]Finding, error) {
	return p.e.scan(LangOf(path), path, src, p, true)
}

func (e *Engine) scan(lang, path string, src []byte, proj *Project, callsOnly bool) ([]Finding, error) {
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
	if proj != nil {
		proj.keep(path, &fileCtx{lang: lang, tree: tree, ff: ff, tokens: len(toks)})
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
				if proj != nil {
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
	for _, r := range rs {
		hs := hasSink(r, toks)
		if !hs && (proj == nil || !hasSource(r, toks)) {
			continue
		}
		ruleList = append(ruleList, r)
		if hs && !callsOnly {
			a := &analysis{r: r, php: lang == "php", py: lang == "python", js: lang == "js", b: b, kw: keywords[lang], seen: map[loc]bool{}, file: path}
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
	callsCut := false
	finished := map[*crule]bool{}
	if !b.hit && (len(ff.byKey) > 0 || proj != nil) {
		b2 := newBudget(e.Limits)
		b2.deadline = b.deadline // one file stays within MaxTime in all
		for _, r := range ruleList {
			sc := newSummaries(ff)
			if proj != nil {
				if sc == nil {
					sc = &summaries{ff: ff, funcs: ff.byKey, done: map[string]*summary{}, busy: map[string]bool{}, rel: map[string]uint8{}, retUnk: map[string]uint8{}}
				}
				proj.sums[r.rule.ID+"\x00"+path] = sc
			}
			a := &analysis{r: r, php: lang == "php", py: lang == "python", js: lang == "js", b: b2, kw: keywords[lang], seen: map[loc]bool{}, sc: sc,
				file: path, proj: proj}
			if !e.Library && !a.crossNeeded(tree) {
				continue // no call can change this rule's result: the first pass stands
			}
			a.block(tree, state{})
			if e.Library && libClasses[r.rule.Class] && !testPath(path) && !b2.hit {
				l := &analysis{r: r, php: a.php, py: a.py, js: a.js, b: b2, kw: a.kw, seen: a.seen, sc: sc, lib: true, file: path, proj: proj}
				l.block(tree, state{})
				a.lines = append(a.lines, l.lines...)
			}
			if b2.hit {
				add(r, direct[r], a.lines) // flows found before the budget ran out are real
				delete(direct, r)
				break
			}
			if sc.capped {
				add(r, direct[r], a.lines)
				delete(direct, r)
				callsCut = true
				continue
			}
			add(r, a.lines)
			finished[r] = true
		}
		callsCut = callsCut || b2.hit || b2.limited
	}
	// Past a project cap calls no longer cross files: say so, not "clean".
	if proj != nil && proj.stopped != "" {
		callsCut = true
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
		return out, ErrLimit
	case b.partial:
		return out, ErrPartial
	case callsCut:
		return out, ErrCalls
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

// hasSource reports whether one of the rule's sources occurs in the file.
func hasSource(r *crule, toks []Token) bool {
	for i := range toks {
		for _, s := range r.sources {
			if s.text == nil && s.at(toks, i, false) {
				return true
			}
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
