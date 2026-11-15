package engine

import (
	"sort"
	"strings"
)

// RouteRef names a route that registers the handler a finding's sink sits in.
// It says only where the sink is, not that request data was traced to it
// along this route: a reader matching web server logs against findings
// (shentu detect) uses it to know which URL reaches the vulnerable code.
//
// It is filled only when that is certain from the one file: the sink is
// inside a function this file registers (a call such as app.get or
// Route::post, a decorator, or a method a framework calls by its class), and
// the innermost such function is the one meant. A handler registered in
// another file (urls.py, routes/web.php) or a sink reached through a call to
// another file gets none. Filling it changes no finding.
type RouteRef struct {
	Model     string `json:"model"`             // the route model's id (rules/routes): express-handler
	Framework string `json:"framework"`         // express, laravel, wordpress, django, fastapi, flask
	Method    string `json:"method,omitempty"`  // the registering call's name in lower case (get, post, any); empty for a decorator or a class method
	Pattern   string `json:"pattern,omitempty"` // the path as written (/users/{id}); for register_rest_route /wp-json/<namespace>/<route>; empty when not a literal
	Handler   string `json:"handler,omitempty"` // the handler function's name; empty for a function literal
	File      string `json:"file"`              // where the route is registered
	Line      int    `json:"line"`              // the registering call's or decorator's line
}

// routeSite is one registration of one handler.
type routeSite struct {
	f   *fn
	ref RouteRef
}

// annotateRoutes fills Routes on the findings of path whose line is inside a
// handler that this file registers. Only the innermost handler holding the
// line counts; a handler registered several times gets one entry for each.
func (e *Engine) annotateRoutes(out []Finding, lang, path string, toks []Token, tree []*stmt, ff *fileFuncs) {
	mine := false
	for i := range out {
		if out[i].Path == path {
			mine = true
			break
		}
	}
	if !mine {
		return
	}
	sites := e.routeSites(lang, path, toks, tree, ff)
	if len(sites) == 0 {
		return
	}
	spans := map[*fn][2]int{}
	for _, s := range sites {
		if _, ok := spans[s.f]; !ok {
			if lo, hi, ok := fnSpan(s.f); ok {
				spans[s.f] = [2]int{lo, hi}
			}
		}
	}
	for i := range out {
		if out[i].Path != path {
			continue
		}
		var best *fn
		for f, sp := range spans {
			if out[i].Line < sp[0] || out[i].Line > sp[1] {
				continue
			}
			if b, ok := spans[best]; best == nil || ok && sp[1]-sp[0] < b[1]-b[0] {
				best = f
			}
		}
		if best == nil {
			continue
		}
		seen := map[RouteRef]bool{}
		for _, s := range sites {
			if s.f == best && !seen[s.ref] {
				seen[s.ref] = true
				out[i].Routes = append(out[i].Routes, s.ref)
			}
		}
		sort.Slice(out[i].Routes, func(a, b int) bool {
			ra, rb := out[i].Routes[a], out[i].Routes[b]
			if ra.Line != rb.Line {
				return ra.Line < rb.Line
			}
			return ra.Model+ra.Method+ra.Pattern < rb.Model+rb.Method+rb.Pattern
		})
	}
}

// routeSites lists every registration of a handler in the file, the way
// handlers finds them, but keeping each one: handlers keeps only the first,
// which is all the taint analysis needs.
func (e *Engine) routeSites(lang, path string, toks []Token, tree []*stmt, ff *fileFuncs) []routeSite {
	var rs []*croute
	for _, c := range e.routes[lang] {
		if len(c.requires) == 0 || namesAny(toks, c.requires) {
			rs = append(rs, c)
		}
	}
	if len(rs) == 0 {
		return nil
	}
	php := lang == "php"
	var out []routeSite
	add := func(c *croute, f *fn, ref RouteRef) {
		if f == nil {
			return
		}
		ref.Model, ref.Framework, ref.File, ref.Handler = c.r.ID, c.r.Framework, path, f.name
		out = append(out, routeSite{f, ref})
	}
	var walk func(ss []*stmt, depth int)
	walk = func(ss []*stmt, depth int) {
		if depth > maxNest {
			return
		}
		var decos [][]Token
		for _, s := range ss {
			if s.kind == sSimple && len(s.toks) > 1 && s.toks[0].op("@") {
				decos = append(decos, s.toks[1:])
				continue
			}
			if s.fn != nil {
				for _, d := range decos {
					for _, c := range rs {
						if t, ok := matchDecorator(d, c.deco); ok {
							add(c, s.fn, RouteRef{Pattern: literal(t), Line: d[0].Line})
						}
					}
				}
				for _, c := range rs {
					if c.r.Extends != "" && strings.EqualFold(s.fn.name, c.r.Method) && s.fn.class != "" &&
						strings.EqualFold(shortClass(s.fn.parent), shortClass(c.r.Extends)) {
						if lo, _, ok := fnSpan(s.fn); ok {
							add(c, s.fn, RouteRef{Line: lo})
						}
					}
				}
			}
			decos = nil
			routeCalls(php, s, rs, ff, add)
			for _, f := range s.funcs {
				walk(f.body, depth+1)
			}
			if s.fn != nil {
				walk(s.fn.body, depth+1)
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
	walk(tree, 0)
	return out
}

// routeCalls is registrations keeping the call: its name, path and line.
func routeCalls(php bool, s *stmt, rs []*croute, ff *fileFuncs, add func(*croute, *fn, RouteRef)) {
	t := s.toks
	for i := 0; i+1 < len(t); i++ {
		if t[i].Kind != Ident || !t[i+1].op("(") {
			continue
		}
		for _, c := range rs {
			if !callMatches(php, t, i, c.register) {
				continue
			}
			args := splitTop(inside(t, i+1, closeOf(t, i+1)), isComma)
			if c.r.Path && (len(args) == 0 || !pathLiteral(args[0])) {
				continue
			}
			k := c.r.Handler - 1
			if c.r.Handler < 0 {
				k = len(args) - 1
			}
			if k < 0 || k >= len(args) {
				continue
			}
			hs := [][]Token{args[k]}
			if c.r.Key != "" {
				hs = routeKeyValues(args[k], c.r.Key)
			}
			ref := RouteRef{Method: strings.ToLower(t[i].Text), Line: t[i].Line}
			if strings.EqualFold(t[i].Text, "register_rest_route") {
				if len(args) >= 2 {
					if ns, r := literal(args[0]), literal(args[1]); ns != "" && r != "" {
						ref.Pattern = "/wp-json/" + strings.Trim(ns, "/") + "/" + strings.TrimLeft(r, "/")
					}
				}
				ref.Method = ""
			} else if len(args) > 0 {
				ref.Pattern = literal(args[0])
			}
			if c.r.Framework == "wordpress" && ref.Method != "" { // add_shortcode and the like: a hook, no HTTP verb
				ref.Method = ""
			}
			for _, h := range hs {
				for _, f := range handlerFuncs(php, s, h, ff) {
					add(c, f, ref)
				}
			}
		}
	}
}

// literal is a single string token's text, or "".
func literal(t []Token) string {
	if len(t) == 1 && t[0].Kind == Str {
		return t[0].Text
	}
	return ""
}

// fnSpan is the first and last line a function's parameters and body reach.
// A decorator above a Python def is not part of it.
func fnSpan(f *fn) (lo, hi int, ok bool) {
	see := func(l int) {
		if l <= 0 {
			return
		}
		if !ok || l < lo {
			lo = l
		}
		if !ok || l > hi {
			hi = l
		}
		ok = true
	}
	for _, t := range f.params {
		see(t.Line)
	}
	var walk func(ss []*stmt, depth int)
	walk = func(ss []*stmt, depth int) {
		if depth > maxNest {
			return
		}
		for _, s := range ss {
			for _, t := range s.toks {
				see(t.Line)
			}
			for _, g := range s.funcs {
				for _, t := range g.params {
					see(t.Line)
				}
				walk(g.body, depth+1)
			}
			if s.fn != nil {
				for _, t := range s.fn.params {
					see(t.Line)
				}
				walk(s.fn.body, depth+1)
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
	walk(f.body, 0)
	return lo, hi, ok
}
